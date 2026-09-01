//! Linux privileged Helper service entrypoint。

#![forbid(unsafe_code)]

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(unix)]
mod linux {
    use nettool_error::{ErrorCode, NetToolError};
    use nettool_helper_core::{
        BeginSafeApply, LinuxNetworkManagerExecutor, LinuxResourceExecutor,
        MacosNetworkStateReader, ManagedHostsEntry, NetworkExecutor, PlatformBackend,
        PlatformNetworkExecutor, SafeApplyManager, SystemCommandRunner, SystemKernelAccess,
        replace_managed_section,
    };
    use nettool_helper_protocol::{PrivilegedOperation, PrivilegedRequest, PrivilegedResponse};
    use nettool_helper_server::{
        AuthorizationPolicy, PrivilegedRequestHandler, error_response, serve_unix_one,
    };
    use serde_json::{Value, json};
    use std::env;
    use std::fs::{self, OpenOptions, Permissions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::UnixListener;
    use tokio::time::{Duration, interval, timeout};

    const WATCHDOG_INTERVAL: Duration = Duration::from_secs(1);
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

    struct Configuration {
        socket_path: PathBuf,
        allowed_uid: u32,
        state_directory: PathBuf,
        hosts_path: PathBuf,
        nmcli_path: PathBuf,
    }

    struct HelperService<E, K> {
        executor: E,
        resources: LinuxResourceExecutor<K>,
        safe_apply: SafeApplyManager,
        hosts_path: PathBuf,
        hosts_backup_path: PathBuf,
    }

    enum UnixNetworkExecutor {
        Linux(LinuxNetworkManagerExecutor<SystemCommandRunner>),
        Macos(
            PlatformNetworkExecutor<
                SystemCommandRunner,
                MacosNetworkStateReader<SystemCommandRunner>,
            >,
        ),
    }

    impl NetworkExecutor for UnixNetworkExecutor {
        fn read_state(&mut self, interface_id: &str) -> Result<Value, NetToolError> {
            match self {
                Self::Linux(executor) => executor.read_state(interface_id),
                Self::Macos(executor) => executor.read_state(interface_id),
            }
        }

        fn snapshot(&mut self, interface_id: &str) -> Result<(String, Value), NetToolError> {
            match self {
                Self::Linux(executor) => executor.snapshot(interface_id),
                Self::Macos(executor) => executor.snapshot(interface_id),
            }
        }

        fn apply(
            &mut self,
            interface_id: &str,
            desired_state: &nettool_helper_protocol::NetworkDesiredState,
        ) -> Result<(), NetToolError> {
            match self {
                Self::Linux(executor) => executor.apply(interface_id, desired_state),
                Self::Macos(executor) => executor.apply(interface_id, desired_state),
            }
        }

        fn verify(
            &mut self,
            interface_id: &str,
            desired_state: &nettool_helper_protocol::NetworkDesiredState,
        ) -> Result<(), NetToolError> {
            match self {
                Self::Linux(executor) => executor.verify(interface_id, desired_state),
                Self::Macos(executor) => executor.verify(interface_id, desired_state),
            }
        }

        fn restore(&mut self, snapshot_id: &str) -> Result<(), NetToolError> {
            match self {
                Self::Linux(executor) => executor.restore(snapshot_id),
                Self::Macos(executor) => executor.restore(snapshot_id),
            }
        }
    }

    impl<E: NetworkExecutor, K: nettool_helper_core::KernelAccess> HelperService<E, K> {
        fn recover_expired(&mut self) -> Result<Vec<String>, NetToolError> {
            self.safe_apply
                .recover_expired(&mut self.executor, now_unix_seconds())
        }

        #[allow(clippy::too_many_lines)]
        fn execute(&mut self, request: &PrivilegedRequest) -> Result<Value, NetToolError> {
            if request.dry_run {
                return Ok(json!({
                    "operation": request.operation.name(),
                    "dry_run": true,
                    "side_effects_performed": false
                }));
            }
            match &request.operation {
                PrivilegedOperation::NetworkReadState { interface_id } => {
                    self.executor.read_state(interface_id)
                }
                PrivilegedOperation::NetworkApply {
                    interface_id,
                    desired_state,
                    confirm_timeout_seconds,
                } => serde_json::to_value(self.safe_apply.begin(
                    &mut self.executor,
                    BeginSafeApply {
                        operation_id: &request.operation_id,
                        interface_id,
                        desired_state,
                        confirm_timeout_seconds: *confirm_timeout_seconds,
                        now_unix_seconds: now_unix_seconds(),
                    },
                )?)
                .map_err(protocol_error),
                PrivilegedOperation::NetworkRestore { snapshot_id } => {
                    self.executor.restore(snapshot_id)?;
                    Ok(json!({"restored": true}))
                }
                PrivilegedOperation::HostsRead => fs::read_to_string(&self.hosts_path)
                    .map(Value::String)
                    .map_err(hosts_io_error),
                PrivilegedOperation::HostsBackup => {
                    let current = fs::read(&self.hosts_path).map_err(hosts_io_error)?;
                    atomic_replace(&self.hosts_backup_path, &current)?;
                    Ok(json!({"backed_up": true, "bytes": current.len()}))
                }
                PrivilegedOperation::HostsRestore => {
                    let backup = fs::read(&self.hosts_backup_path).map_err(hosts_io_error)?;
                    atomic_replace(&self.hosts_path, &backup)?;
                    Ok(json!({"restored": true, "bytes": backup.len()}))
                }
                PrivilegedOperation::HostsAtomicReplace {
                    profile_id,
                    entries,
                } => {
                    let current = fs::read_to_string(&self.hosts_path).map_err(hosts_io_error)?;
                    let entries = entries
                        .iter()
                        .map(|entry| {
                            Ok(ManagedHostsEntry {
                                address: entry.address.parse().map_err(|_| {
                                    NetToolError::new(
                                        ErrorCode::InvalidArgument,
                                        "hosts address is invalid",
                                        false,
                                    )
                                })?,
                                hostname: entry.hostname.clone(),
                                comment: entry.comment.clone(),
                                enabled: entry.enabled,
                            })
                        })
                        .collect::<Result<Vec<_>, NetToolError>>()?;
                    let updated = replace_managed_section(&current, profile_id, &entries)?;
                    atomic_replace(&self.hosts_path, updated.as_bytes())?;
                    Ok(json!({"updated": true, "entry_count": entries.len()}))
                }
                PrivilegedOperation::SafeApplyConfirm { operation_id } => {
                    serde_json::to_value(self.safe_apply.confirm(operation_id)?)
                        .map_err(protocol_error)
                }
                PrivilegedOperation::SafeApplyRollback { operation_id } => {
                    self.safe_apply.rollback(&mut self.executor, operation_id)?;
                    Ok(json!({"rolled_back": true}))
                }
                PrivilegedOperation::SafeApplyListPending => {
                    serde_json::to_value(self.safe_apply.pending()).map_err(protocol_error)
                }
                PrivilegedOperation::NicPrepareDpdk { pci_address } => serde_json::to_value(
                    self.resources
                        .prepare_dpdk(&request.operation_id, pci_address)?,
                )
                .map_err(protocol_error),
                PrivilegedOperation::NicRestoreDriver {
                    pci_address,
                    prepare_operation_id,
                } => serde_json::to_value(
                    self.resources
                        .restore_driver(prepare_operation_id, pci_address)?,
                )
                .map_err(protocol_error),
                PrivilegedOperation::HugepagePrepare {
                    node,
                    pages,
                    page_size_kib,
                } => serde_json::to_value(self.resources.prepare_hugepages(
                    &request.operation_id,
                    *node,
                    *pages,
                    *page_size_kib,
                )?)
                .map_err(protocol_error),
                PrivilegedOperation::HugepageRelease { operation_id } => {
                    serde_json::to_value(self.resources.release_hugepages(operation_id)?)
                        .map_err(protocol_error)
                }
            }
        }
    }

    impl<E: NetworkExecutor, K: nettool_helper_core::KernelAccess> PrivilegedRequestHandler
        for HelperService<E, K>
    {
        fn handle(&mut self, request: PrivilegedRequest) -> PrivilegedResponse {
            let started = std::time::Instant::now();
            let request_id = request.request_id.clone();
            let operation = request.operation.name();
            tracing::info!(request_id = %request_id, operation = %operation, "helper request started");
            match self.execute(&request) {
                Ok(result) => {
                    tracing::info!(request_id = %request_id, operation = %operation, success = true, elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), "helper request completed");
                    PrivilegedResponse {
                        request_id: request.request_id,
                        result: Some(result),
                        error: None,
                    }
                }
                Err(error) => {
                    tracing::warn!(request_id = %request_id, operation = %operation, success = false, error_code = %error.code.as_str(), elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), "helper request failed");
                    error_response(request.request_id, &error)
                }
            }
        }
    }

    pub async fn run() -> Result<(), NetToolError> {
        let configuration = parse_arguments(env::args().skip(1))?;
        for path in [
            &configuration.socket_path,
            &configuration.state_directory,
            &configuration.hosts_path,
            &configuration.nmcli_path,
        ] {
            if !path.is_absolute() {
                return Err(NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "all helper paths must be absolute",
                    false,
                ));
            }
        }
        if configuration.socket_path.exists() {
            return Err(NetToolError::new(
                ErrorCode::ResourceConflict,
                "helper socket path already exists",
                false,
            ));
        }
        let snapshot_directory = configuration.state_directory.join("snapshots");
        let executor = if cfg!(target_os = "macos") {
            UnixNetworkExecutor::Macos(PlatformNetworkExecutor::new(
                SystemCommandRunner,
                MacosNetworkStateReader::new(SystemCommandRunner),
                PlatformBackend::Macos,
                snapshot_directory,
            )?)
        } else {
            UnixNetworkExecutor::Linux(LinuxNetworkManagerExecutor::new(
                SystemCommandRunner,
                &configuration.nmcli_path,
                snapshot_directory,
            )?)
        };
        let safe_apply = SafeApplyManager::open(
            configuration.state_directory.join("safe-apply.json"),
            configuration.state_directory.join("audit.jsonl"),
        )?;
        let resources = LinuxResourceExecutor::new(
            SystemKernelAccess,
            "/sys",
            configuration.state_directory.join("resources"),
        )?;
        let hosts_backup_path = configuration.state_directory.join("hosts.backup");
        if !hosts_backup_path.exists() {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&hosts_backup_path)
                .map_err(hosts_io_error)?;
            fs::set_permissions(&hosts_backup_path, Permissions::from_mode(0o600))
                .map_err(hosts_io_error)?;
        }
        let mut service = HelperService {
            executor,
            resources,
            safe_apply,
            hosts_path: configuration.hosts_path,
            hosts_backup_path,
        };
        service.recover_expired()?;

        if let Some(parent) = configuration.socket_path.parent() {
            fs::create_dir_all(parent).map_err(hosts_io_error)?;
        }
        let listener = UnixListener::bind(&configuration.socket_path).map_err(transport_error)?;
        fs::set_permissions(&configuration.socket_path, Permissions::from_mode(0o660))
            .map_err(transport_error)?;
        let policy = AuthorizationPolicy::new([configuration.allowed_uid.to_string()]);
        let mut watchdog = interval(WATCHDOG_INTERVAL);
        loop {
            tokio::select! {
                _ = watchdog.tick() => {
                    if let Err(error) = service.recover_expired() {
                        eprintln!("{}", error.code.as_str());
                    }
                }
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.map_err(transport_error)?;
                    match timeout(
                        REQUEST_TIMEOUT,
                        serve_unix_one(&mut stream, &policy, &mut service),
                    ).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => eprintln!("{}", error.code.as_str()),
                        Err(_) => eprintln!("HELPER.REQUEST_TIMEOUT"),
                    }
                }
            }
        }
    }

    fn parse_arguments(
        arguments: impl IntoIterator<Item = String>,
    ) -> Result<Configuration, NetToolError> {
        let mut socket_path = None;
        let mut allowed_uid = None;
        let mut state_directory = None;
        let mut hosts_path = None;
        let mut nmcli_path = PathBuf::from("/usr/bin/nmcli");
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let value = arguments.next().ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("missing value for {argument}"),
                    false,
                )
            })?;
            match argument.as_str() {
                "--socket" => socket_path = Some(PathBuf::from(value)),
                "--allow-uid" => {
                    allowed_uid = Some(value.parse::<u32>().map_err(|_| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            "allow UID must be an unsigned integer",
                            false,
                        )
                    })?);
                }
                "--state-dir" => state_directory = Some(PathBuf::from(value)),
                "--hosts-file" => hosts_path = Some(PathBuf::from(value)),
                "--nmcli" => nmcli_path = PathBuf::from(value),
                _ => {
                    return Err(NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("unknown helper argument: {argument}"),
                        false,
                    ));
                }
            }
        }
        Ok(Configuration {
            socket_path: required(socket_path, "--socket")?,
            allowed_uid: required(allowed_uid, "--allow-uid")?,
            state_directory: required(state_directory, "--state-dir")?,
            hosts_path: required(hosts_path, "--hosts-file")?,
            nmcli_path,
        })
    }

    fn required<T>(value: Option<T>, name: &str) -> Result<T, NetToolError> {
        value.ok_or_else(|| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("required helper argument is missing: {name}"),
                false,
            )
        })
    }

    fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), NetToolError> {
        let metadata = fs::metadata(path).map_err(hosts_io_error)?;
        let temporary = path.with_extension("nettool.tmp");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(hosts_io_error)?;
        fs::set_permissions(&temporary, metadata.permissions()).map_err(hosts_io_error)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(hosts_io_error)?;
        fs::rename(&temporary, path).map_err(hosts_io_error)?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(hosts_io_error)?;
        }
        Ok(())
    }

    fn now_unix_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }

    #[allow(clippy::needless_pass_by_value)]
    fn protocol_error(error: serde_json::Error) -> NetToolError {
        NetToolError::new(
            ErrorCode::ProtocolInvalid,
            format!("encode helper result: {error}"),
            false,
        )
    }

    #[allow(clippy::needless_pass_by_value)]
    fn hosts_io_error(error: std::io::Error) -> NetToolError {
        NetToolError::new(
            ErrorCode::PersistenceFailed,
            format!("helper file operation failed: {error}"),
            true,
        )
    }

    #[allow(clippy::needless_pass_by_value)]
    fn transport_error(error: std::io::Error) -> NetToolError {
        NetToolError::new(
            ErrorCode::HelperTransportFailed,
            format!("helper Unix socket failed: {error}"),
            true,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::parse_arguments;

        #[test]
        fn requires_explicit_uid_and_absolute_service_paths() {
            let configuration = parse_arguments([
                "--socket".into(),
                "/run/nettool/helper.sock".into(),
                "--allow-uid".into(),
                "1000".into(),
                "--state-dir".into(),
                "/var/lib/nettool/helper".into(),
                "--hosts-file".into(),
                "/etc/hosts".into(),
            ])
            .expect("valid arguments");
            assert_eq!(configuration.allowed_uid, 1000);
            assert!(configuration.socket_path.is_absolute());
        }

        #[test]
        fn rejects_unknown_arguments() {
            assert!(parse_arguments(["--execute".into(), "id".into()]).is_err());
        }
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() {
    init_logging();
    if let Err(error) = linux::run().await {
        eprintln!("{}: {}", error.code.as_str(), error.message);
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod windows {
    use nettool_error::{ErrorCode, NetToolError};
    use nettool_helper_core::{
        BeginSafeApply, ManagedHostsEntry, NetworkExecutor, PlatformBackend,
        PlatformNetworkExecutor, SafeApplyManager, SystemCommandRunner, WindowsNetshStateReader,
        replace_managed_section,
    };
    use nettool_helper_protocol::{PrivilegedOperation, PrivilegedRequest, PrivilegedResponse};
    use nettool_helper_server::{
        AuthorizationPolicy, PrivilegedRequestHandler, error_response, serve_named_pipe_one,
    };
    use serde_json::{Value, json};
    use std::env;
    use std::fs::{self, OpenOptions};
    use std::path::{Path, PathBuf};
    use std::time::Instant;
    use tokio::net::windows::named_pipe::ServerOptions;
    use tokio::time::{Duration, interval, timeout};

    const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

    struct Service {
        executor: PlatformNetworkExecutor<
            SystemCommandRunner,
            WindowsNetshStateReader<SystemCommandRunner>,
        >,
        safe_apply: SafeApplyManager,
        hosts_path: PathBuf,
        hosts_backup_path: PathBuf,
    }

    impl Service {
        fn execute(&mut self, request: &PrivilegedRequest) -> Result<Value, NetToolError> {
            if request.dry_run {
                return Ok(json!({
                    "operation": request.operation.name(),
                    "dry_run": true,
                    "side_effects_performed": false
                }));
            }
            match &request.operation {
                PrivilegedOperation::NetworkReadState { interface_id } => {
                    self.executor.read_state(interface_id)
                }
                PrivilegedOperation::NetworkApply {
                    interface_id,
                    desired_state,
                    confirm_timeout_seconds,
                } => serde_json::to_value(self.safe_apply.begin(
                    &mut self.executor,
                    BeginSafeApply {
                        operation_id: &request.operation_id,
                        interface_id,
                        desired_state,
                        confirm_timeout_seconds: *confirm_timeout_seconds,
                        now_unix_seconds: now_unix_seconds(),
                    },
                )?)
                .map_err(protocol_error),
                PrivilegedOperation::NetworkRestore { snapshot_id } => {
                    self.executor.restore(snapshot_id)?;
                    Ok(json!({"restored": true}))
                }
                PrivilegedOperation::SafeApplyConfirm { operation_id } => {
                    serde_json::to_value(self.safe_apply.confirm(operation_id)?)
                        .map_err(protocol_error)
                }
                PrivilegedOperation::SafeApplyRollback { operation_id } => {
                    self.safe_apply.rollback(&mut self.executor, operation_id)?;
                    Ok(json!({"rolled_back": true}))
                }
                PrivilegedOperation::SafeApplyListPending => {
                    serde_json::to_value(self.safe_apply.pending()).map_err(protocol_error)
                }
                PrivilegedOperation::HostsRead => fs::read_to_string(&self.hosts_path)
                    .map(Value::String)
                    .map_err(io_error),
                PrivilegedOperation::HostsBackup => {
                    let bytes = fs::read(&self.hosts_path).map_err(io_error)?;
                    atomic_replace(&self.hosts_backup_path, &bytes)?;
                    Ok(json!({"backed_up": true, "bytes": bytes.len()}))
                }
                PrivilegedOperation::HostsRestore => {
                    let bytes = fs::read(&self.hosts_backup_path).map_err(io_error)?;
                    atomic_replace(&self.hosts_path, &bytes)?;
                    Ok(json!({"restored": true, "bytes": bytes.len()}))
                }
                PrivilegedOperation::HostsAtomicReplace {
                    profile_id,
                    entries,
                } => {
                    let current = fs::read_to_string(&self.hosts_path).map_err(io_error)?;
                    let entries = entries
                        .iter()
                        .map(|entry| {
                            Ok(ManagedHostsEntry {
                                address: entry
                                    .address
                                    .parse()
                                    .map_err(|_| invalid("hosts address is invalid"))?,
                                hostname: entry.hostname.clone(),
                                comment: entry.comment.clone(),
                                enabled: entry.enabled,
                            })
                        })
                        .collect::<Result<Vec<_>, NetToolError>>()?;
                    let updated = replace_managed_section(&current, profile_id, &entries)?;
                    atomic_replace(&self.hosts_path, updated.as_bytes())?;
                    Ok(json!({"updated": true, "entry_count": entries.len()}))
                }
                _ => Err(NetToolError::new(
                    ErrorCode::Unsupported,
                    "Windows helper operation is not attached",
                    false,
                )),
            }
        }
    }

    impl PrivilegedRequestHandler for Service {
        fn handle(&mut self, request: PrivilegedRequest) -> PrivilegedResponse {
            let started = std::time::Instant::now();
            let request_id = request.request_id.clone();
            let operation = request.operation.name();
            tracing::info!(request_id = %request_id, operation = %operation, "helper request started");
            match self.execute(&request) {
                Ok(result) => {
                    tracing::info!(request_id = %request_id, operation = %operation, success = true, elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), "helper request completed");
                    PrivilegedResponse {
                        request_id: request.request_id,
                        result: Some(result),
                        error: None,
                    }
                }
                Err(error) => {
                    tracing::warn!(request_id = %request_id, operation = %operation, success = false, error_code = %error.code.as_str(), elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), "helper request failed");
                    error_response(request.request_id, &error)
                }
            }
        }
    }

    pub async fn run() -> Result<(), NetToolError> {
        let configuration = parse_arguments(env::args().skip(1))?;
        let snapshot_directory = configuration.state_directory.join("snapshots");
        let executor = PlatformNetworkExecutor::new(
            SystemCommandRunner,
            WindowsNetshStateReader::new(SystemCommandRunner),
            PlatformBackend::Windows,
            snapshot_directory,
        )?;
        let safe_apply = SafeApplyManager::open(
            configuration.state_directory.join("safe-apply.json"),
            configuration.state_directory.join("audit.jsonl"),
        )?;
        let hosts_backup_path = configuration.state_directory.join("hosts.backup");
        if !hosts_backup_path.exists() {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&hosts_backup_path)
                .map_err(io_error)?;
        }
        let mut service = Service {
            executor,
            safe_apply,
            hosts_path: configuration.hosts_path,
            hosts_backup_path,
        };
        let policy = AuthorizationPolicy::new([configuration.allowed_sid]);
        let mut listener = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&configuration.pipe_path)
            .map_err(pipe_error)?;
        let mut watchdog = interval(Duration::from_secs(1));
        let mut last_request = Instant::now();
        let mut has_started_safe_apply = false;
        loop {
            tokio::select! {
                result = listener.connect() => {
                    result.map_err(pipe_error)?;
                    last_request = Instant::now();
                    let mut connected = listener;
                    listener = ServerOptions::new().create(&configuration.pipe_path).map_err(pipe_error)?;
                    match timeout(REQUEST_TIMEOUT, serve_named_pipe_one(&mut connected, &policy, &mut service)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => eprintln!("{}", error.code.as_str()),
                        Err(_) => eprintln!("HELPER.REQUEST_TIMEOUT"),
                    }
                    has_started_safe_apply |= !service.safe_apply.pending().is_empty();
                }
                _ = watchdog.tick() => {
                    service.safe_apply.recover_expired(&mut service.executor, now_unix_seconds())?;
                    if has_started_safe_apply && service.safe_apply.pending().is_empty() {
                        tracing::info!("portable Helper completed Safe Apply and will exit");
                        return Ok(());
                    }
                    if configuration.idle_timeout.is_some_and(|timeout| !has_started_safe_apply && last_request.elapsed() >= timeout) {
                        tracing::info!("portable Helper idle timeout completed without pending Safe Apply");
                        return Ok(());
                    }
                    if nettool_platform_auth::windows_service_stop_requested() && service.safe_apply.pending().is_empty() {
                        tracing::info!("helper stop completed after Safe Apply state settled");
                        return Ok(());
                    }
                }
            }
        }
    }

    struct Configuration {
        pipe_path: String,
        allowed_sid: String,
        state_directory: PathBuf,
        hosts_path: PathBuf,
        idle_timeout: Option<Duration>,
    }

    fn parse_arguments(
        arguments: impl IntoIterator<Item = String>,
    ) -> Result<Configuration, NetToolError> {
        let mut pipe_path = None;
        let mut allowed_sid = None;
        let mut state_directory = None;
        let mut hosts_path = None;
        let mut idle_timeout = None;
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let target = match argument.as_str() {
                "--pipe" => &mut pipe_path,
                "--allow-sid" => &mut allowed_sid,
                "--state-dir" => &mut state_directory,
                "--hosts-file" => &mut hosts_path,
                "--idle-timeout-seconds" => &mut idle_timeout,
                "--service" => continue,
                _ => return Err(invalid("unknown helper argument")),
            };
            *target = Some(
                arguments
                    .next()
                    .ok_or_else(|| invalid("helper argument value is missing"))?,
            );
        }
        let pipe_path = pipe_path.ok_or_else(|| invalid("--pipe is required"))?;
        let allowed_sid = allowed_sid.ok_or_else(|| invalid("--allow-sid is required"))?;
        let state_directory =
            PathBuf::from(state_directory.ok_or_else(|| invalid("--state-dir is required"))?);
        let hosts_path =
            PathBuf::from(hosts_path.ok_or_else(|| invalid("--hosts-file is required"))?);
        let idle_timeout = idle_timeout
            .map(|value| {
                value
                    .parse::<u64>()
                    .ok()
                    .filter(|seconds| (10..=600).contains(seconds))
                    .map(Duration::from_secs)
                    .ok_or_else(|| invalid("--idle-timeout-seconds must be between 10 and 600"))
            })
            .transpose()?;
        if !pipe_path.starts_with(r"\\.\pipe\")
            || !state_directory.is_absolute()
            || !hosts_path.is_absolute()
        {
            return Err(invalid("helper paths are invalid"));
        }
        fs::create_dir_all(&state_directory).map_err(io_error)?;
        Ok(Configuration {
            pipe_path,
            allowed_sid,
            state_directory,
            hosts_path,
            idle_timeout,
        })
    }

    fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), NetToolError> {
        nettool_platform_auth::atomic_replace_file(path, bytes)
            .map_err(|message| NetToolError::new(ErrorCode::PersistenceFailed, message, true))
    }

    fn now_unix_seconds() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }

    fn invalid(message: &str) -> NetToolError {
        NetToolError::new(ErrorCode::InvalidArgument, message, false)
    }
    #[allow(clippy::needless_pass_by_value)]
    fn io_error(error: std::io::Error) -> NetToolError {
        NetToolError::new(ErrorCode::PersistenceFailed, error.to_string(), true)
    }
    #[allow(clippy::needless_pass_by_value)]
    fn pipe_error(error: std::io::Error) -> NetToolError {
        NetToolError::new(ErrorCode::HelperTransportFailed, error.to_string(), true)
    }
    #[allow(clippy::needless_pass_by_value)]
    fn protocol_error(error: serde_json::Error) -> NetToolError {
        NetToolError::new(ErrorCode::ProtocolInvalid, error.to_string(), false)
    }

    #[cfg(test)]
    mod tests {
        use super::parse_arguments;

        #[test]
        fn portable_arguments_accept_a_bounded_idle_timeout() {
            let root = std::env::temp_dir()
                .join(format!("nettool-helper-test-{}-valid", std::process::id()));
            let state = root.join("state");
            let hosts = root.join("hosts");
            let configuration = parse_arguments([
                "--pipe".to_owned(),
                r"\\.\pipe\NetTool.Helper.Portable.test".to_owned(),
                "--allow-sid".to_owned(),
                "S-1-5-21-test".to_owned(),
                "--state-dir".to_owned(),
                state.display().to_string(),
                "--hosts-file".to_owned(),
                hosts.display().to_string(),
                "--idle-timeout-seconds".to_owned(),
                "120".to_owned(),
            ])
            .expect("portable arguments are valid");
            assert_eq!(
                configuration.idle_timeout.map(|value| value.as_secs()),
                Some(120)
            );
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn portable_arguments_reject_an_unbounded_idle_timeout() {
            let root = std::env::temp_dir().join(format!(
                "nettool-helper-test-{}-invalid",
                std::process::id()
            ));
            let state = root.join("state");
            let hosts = root.join("hosts");
            assert!(
                parse_arguments([
                    "--pipe".to_owned(),
                    r"\\.\pipe\NetTool.Helper.Portable.test".to_owned(),
                    "--allow-sid".to_owned(),
                    "S-1-5-21-test".to_owned(),
                    "--state-dir".to_owned(),
                    state.display().to_string(),
                    "--hosts-file".to_owned(),
                    hosts.display().to_string(),
                    "--idle-timeout-seconds".to_owned(),
                    "601".to_owned(),
                ])
                .is_err()
            );
        }
    }
}

#[cfg(windows)]
fn run_windows_service_workload() -> Result<(), String> {
    tokio::runtime::Runtime::new()
        .map_err(|error| error.to_string())
        .and_then(|runtime| {
            runtime
                .block_on(windows::run())
                .map_err(|error| error.message)
        })
}

#[cfg(windows)]
fn main() {
    init_logging();
    let service_mode = std::env::args().any(|argument| argument == "--service");
    let result = if service_mode {
        nettool_platform_auth::run_windows_service("NetToolHelper", run_windows_service_workload)
            .map_err(|message| {
                nettool_error::NetToolError::new(
                    nettool_error::ErrorCode::HelperTransportFailed,
                    message,
                    false,
                )
            })
    } else {
        tokio::runtime::Runtime::new()
            .map_err(|error| {
                nettool_error::NetToolError::new(
                    nettool_error::ErrorCode::HelperTransportFailed,
                    error.to_string(),
                    false,
                )
            })
            .and_then(|runtime| runtime.block_on(windows::run()))
    };
    if let Err(error) = result {
        eprintln!("{}: {}", error.code.as_str(), error.message);
        std::process::exit(1);
    }
}

#[cfg(all(not(unix), not(windows)))]
fn main() {
    init_logging();
    eprintln!("PLATFORM.UNSUPPORTED: nettool-helper has no supported transport on this platform");
    std::process::exit(1);
}
