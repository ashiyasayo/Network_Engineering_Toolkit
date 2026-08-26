//! `NetTool` 唯一 runtime authority 的本機 IPC 入口。

#![forbid(unsafe_code)]

#[cfg(any(unix, windows))]
mod agent_runtime {
    // 保留 action 的 runtime namespace，並讓各平台 formatter 以 src 目錄解析來源檔案。
    mod action_dispatch {
        include!("action_dispatch.rs");
    }
    mod action_helper {
        include!("action_helper.rs");
    }
    mod action_hosts {
        include!("action_hosts.rs");
    }
    mod action_node {
        include!("action_node.rs");
    }
    mod action_packet {
        include!("action_packet.rs");
    }
    mod action_perf {
        include!("action_perf.rs");
    }
    mod action_persistent {
        include!("action_persistent.rs");
    }
    mod action_profile {
        include!("action_profile.rs");
    }
    mod action_speed {
        include!("action_speed.rs");
    }
    use action_speed::{parse_node_id, utc_timestamp};

    use nettool_action::{ActionRegistry, PermissionRequirement};
    use nettool_agent_client::default_socket_path;
    use nettool_agent_protocol::{
        ActionResponse, AgentEnvelope, MAX_FRAME_BYTES, PROTOCOL_MAJOR, PROTOCOL_MINOR,
        agent_envelope, decode_payload, encode_frame,
    };
    use nettool_backend_dpdk::probe_environment;
    use nettool_backend_pcap::CaptureFileSource;
    use nettool_benchmark::BenchmarkProfileRegistry;
    use nettool_error::{ErrorCode, NetToolError};
    use nettool_helper_protocol::{
        ManagedHostsEntry, NetworkDesiredState, PrivilegedOperation, PrivilegedResponse,
        PrivilegedWireRequest,
    };
    use nettool_identity::{IdentityMaterial, IdentityProvider, PlatformKeyringStore};
    use nettool_node::{
        LocalDataPlanePorts, LocalNodeIdentity, NodeControlService, PreparedSocketBidirectional,
        PreparedSocketReceiver, PreparedSocketSender, SessionCoordinator, TrustedNodeEndpoint,
        certificate_public_key_fingerprint, connect_control_client, prepare_remote_speed_session,
        random_session_id, read_control_frame, tls13_client_config, tls13_server_config,
        write_control_frame,
    };
    use nettool_node_protocol::StopTest;
    use nettool_packet::{AnalysisCoverage, PacketWorker, PacketWorkerConfiguration, StopToken};
    use nettool_speed::{
        AuthorizedTcpSenderConfig, SpeedRunRequest, TcpRunConfig, UdpSenderConfig,
        run_authorized_tcp_receiver, run_authorized_tcp_sender, run_udp_receiver, run_udp_sender,
    };
    use nettool_storage::{
        SpeedSessionPersistenceRequest, Storage, TrustedNodeConnection, TrustedNodeSummary,
    };
    use rustls::RootCertStore;
    use rustls_pki_types::CertificateDer;
    use serde::Deserialize;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fmt::Write as FmtWrite;
    use std::fs;
    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(windows)]
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, ServerOptions};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    #[cfg(unix)]
    use tokio::net::{UnixListener, UnixStream};
    use tokio::process::{Child, Command as TokioCommand};
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, sleep};
    use tokio_rustls::{TlsAcceptor, server::TlsStream};

    const DEFAULT_UDP_DATAGRAM_BYTES_U16: u16 = 1_200;

    pub async fn run() -> Result<(), String> {
        init_logging();
        let socket_path = default_socket_path();
        #[cfg(unix)]
        prepare_socket(&socket_path)?;
        let database_path = database_path();
        if let Some(parent) = database_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create data directory: {error}"))?;
        }
        let storage = Storage::open(&database_path).map_err(|error| error.to_string())?;
        // Agent 啟動即取得平台安全身分，避免第一個遠端 request 才發現私鑰不可用。
        let (identity_material, local_identity) = load_platform_identity()?;
        let runtime = Arc::new(AgentRuntime {
            storage: Arc::new(Mutex::new(storage)),
            identity_material,
            local_identity,
            node_coordinator: Arc::new(Mutex::new(SessionCoordinator::new())),
            capture_children: Arc::new(Mutex::new(HashMap::new())),
        });
        let _control_server = start_control_server(&runtime).await?;
        println!(
            "nettool-agent node {} listening on {}",
            hex_node_id(runtime.local_identity.node_id),
            socket_path.display()
        );
        #[cfg(unix)]
        {
            let listener = UnixListener::bind(&socket_path)
                .map_err(|error| format!("cannot bind {}: {error}", socket_path.display()))?;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("cannot secure agent socket: {error}"))?;
            loop {
                let (stream, _) = listener
                    .accept()
                    .await
                    .map_err(|error| format!("agent accept failed: {error}"))?;
                spawn_client(stream, Arc::clone(&runtime));
            }
        }
        #[cfg(windows)]
        {
            let mut listener = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&socket_path)
                .map_err(|error| format!("cannot create Agent Named Pipe: {error}"))?;
            loop {
                listener
                    .connect()
                    .await
                    .map_err(|error| format!("agent Named Pipe connect failed: {error}"))?;
                let connected = listener;
                listener = ServerOptions::new()
                    .create(&socket_path)
                    .map_err(|error| format!("cannot create next Agent Named Pipe: {error}"))?;
                spawn_client(connected, Arc::clone(&runtime));
            }
        }
    }

    fn spawn_client<S>(stream: S, runtime: Arc<AgentRuntime>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            if let Err(error) = handle_client(stream, &runtime).await {
                tracing::error!(operation = "agent.client", error = %error, "agent client failed");
            }
        });
    }

    fn init_logging() {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init();
    }

    struct AgentRuntime {
        storage: Arc<Mutex<Storage>>,
        identity_material: IdentityMaterial,
        local_identity: LocalNodeIdentity,
        node_coordinator: Arc<Mutex<SessionCoordinator>>,
        capture_children: Arc<Mutex<HashMap<String, Child>>>,
    }

    async fn start_control_server(
        runtime: &AgentRuntime,
    ) -> Result<Option<JoinHandle<()>>, String> {
        let Some(address) = std::env::var_os("NETTOOL_CONTROL_LISTEN") else {
            return Ok(None);
        };
        let address = address
            .to_string_lossy()
            .parse::<SocketAddr>()
            .map_err(|_| {
                "NETTOOL_CONTROL_LISTEN must be an explicit IP:port socket address".to_owned()
            })?;
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| format!("cannot bind Node control listener {address}: {error}"))?;
        println!(
            "nettool-agent Node control listening on {}",
            listener
                .local_addr()
                .map_err(|error| format!("cannot inspect Node control listener: {error}"))?
        );
        let storage = Arc::clone(&runtime.storage);
        let certificate_chain = runtime.identity_material.certificate_chain.clone();
        let private_key = runtime.identity_material.private_key.clone_key();
        let local = runtime.local_identity.clone();
        let coordinator = Arc::clone(&runtime.node_coordinator);
        Ok(Some(tokio::spawn(async move {
            loop {
                let accepted = listener.accept().await;
                let (stream, peer_address) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!(operation = "node.control.accept", error = %error, "Node control accept failed");
                        continue;
                    }
                };
                let storage = Arc::clone(&storage);
                let certificate_chain = certificate_chain.clone();
                let private_key = private_key.clone_key();
                let local = local.clone();
                let coordinator = Arc::clone(&coordinator);
                tokio::spawn(async move {
                    if let Err(error) = accept_node_connection(
                        stream,
                        peer_address,
                        storage,
                        certificate_chain,
                        private_key,
                        local,
                        coordinator,
                    )
                    .await
                    {
                        tracing::error!(operation = "node.control.connection", peer = %peer_address, error = %error, "Node control connection failed");
                    }
                });
            }
        })))
    }

    async fn accept_node_connection(
        stream: TcpStream,
        peer_address: SocketAddr,
        storage: Arc<Mutex<Storage>>,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: rustls_pki_types::PrivateKeyDer<'static>,
        local: LocalNodeIdentity,
        coordinator: Arc<Mutex<SessionCoordinator>>,
    ) -> Result<(), String> {
        let trusted_peers = storage
            .lock()
            .await
            .list_trusted_nodes()
            .map_err(|error| error.to_string())?;
        validate_trusted_peers(&trusted_peers)?;
        if trusted_peers.is_empty() {
            // Pairing 可先經本機 Agent IPC 完成；尚未有 trust 時，新 control connection 只會被拒絕。
            return Err("Node control connection rejected: no trusted peers".to_owned());
        }
        let mut client_roots = RootCertStore::empty();
        for peer in &trusted_peers {
            client_roots
                .add(CertificateDer::from(peer.certificate_der.clone()))
                .map_err(|error| format!("cannot trust paired Node certificate: {error}"))?;
        }
        let server_config = tls13_server_config(certificate_chain, private_key, client_roots)
            .map_err(|error| error.to_string())?;
        handle_node_connection(
            stream,
            peer_address,
            TlsAcceptor::from(Arc::new(server_config)),
            trusted_peers,
            local,
            coordinator,
        )
        .await
    }

    fn validate_trusted_peers(peers: &[TrustedNodeSummary]) -> Result<(), String> {
        for (index, peer) in peers.iter().enumerate() {
            if peers[index + 1..].iter().any(|other| {
                other.fingerprint.eq_ignore_ascii_case(&peer.fingerprint) && other.id != peer.id
            }) {
                return Err("trusted fingerprint maps to multiple Node IDs".to_owned());
            }
        }
        Ok(())
    }

    async fn handle_node_connection(
        stream: TcpStream,
        peer_address: SocketAddr,
        acceptor: TlsAcceptor,
        trusted_peers: Vec<TrustedNodeSummary>,
        local: LocalNodeIdentity,
        coordinator: Arc<Mutex<SessionCoordinator>>,
    ) -> Result<(), String> {
        let mut stream = acceptor
            .accept(stream)
            .await
            .map_err(|error| format!("Node mutual TLS failed: {error}"))?;
        let fingerprint = peer_fingerprint(&stream)?;
        let peer = trusted_peers
            .into_iter()
            .find(|peer| peer.fingerprint.eq_ignore_ascii_case(&fingerprint))
            .ok_or_else(|| "authenticated certificate is not in the trusted registry".to_owned())?;
        let peer_node_id = parse_node_id(&peer.id).map_err(|error| error.to_string())?;
        let local_address = stream
            .get_ref()
            .0
            .local_addr()
            .map_err(|error| format!("cannot inspect Node local address: {error}"))?;
        let mut service = NodeControlService::with_coordinator(
            local,
            peer_node_id,
            peer_address.ip(),
            local_address.ip(),
            Arc::clone(&coordinator),
        );
        loop {
            let request = read_control_frame(&mut stream)
                .await
                .map_err(|error| error.to_string())?;
            let scheduled = request.message.as_ref().and_then(|message| {
                if let nettool_node_protocol::envelope::ControlMessage::StartTest(start) = message {
                    parse_wire_session_id(&start.session_id)
                        .ok()
                        .map(|session_id| (session_id, start.start_at_unix_nanoseconds))
                } else {
                    None
                }
            });
            let response = service
                .dispatch(request, now_unix_nanoseconds())
                .await
                .map_err(|error| error.to_string())?;
            write_control_frame(&mut stream, &response)
                .await
                .map_err(|error| error.to_string())?;
            let start_accepted = matches!(
                response.message,
                Some(nettool_node_protocol::envelope::ControlMessage::TestStatus(ref status))
                    if matches!(status.state.as_str(), "TEST_READY" | "RUNNING")
            );
            if let Some((session_id, start_at)) = scheduled.filter(|_| start_accepted) {
                spawn_scheduled_worker(Arc::clone(&coordinator), session_id, start_at);
            }
        }
    }

    enum PreparedSocketWorker {
        Receiver(PreparedSocketReceiver),
        Sender(PreparedSocketSender),
        Bidirectional(PreparedSocketBidirectional),
    }

    fn spawn_scheduled_worker(
        coordinator: Arc<Mutex<SessionCoordinator>>,
        session_id: [u8; 16],
        start_at_unix_nanoseconds: u64,
    ) {
        tokio::spawn(async move {
            let now = now_unix_nanoseconds();
            if start_at_unix_nanoseconds > now {
                sleep(Duration::from_nanos(start_at_unix_nanoseconds - now)).await;
            }
            let worker = {
                let mut coordinator = coordinator.lock().await;
                match coordinator.begin_and_take_bidirectional(session_id, now_unix_nanoseconds()) {
                    Ok(worker) => PreparedSocketWorker::Bidirectional(worker),
                    Err(_) => match coordinator
                        .begin_and_take_receiver(session_id, now_unix_nanoseconds())
                    {
                        Ok(receiver) => PreparedSocketWorker::Receiver(receiver),
                        Err(_) => match coordinator
                            .begin_and_take_sender(session_id, now_unix_nanoseconds())
                        {
                            Ok(sender) => PreparedSocketWorker::Sender(sender),
                            // 冪等 Start 可能產生重複 scheduler；只有取得 endpoint 的 task 可執行 worker。
                            Err(_) => return,
                        },
                    },
                }
            };
            let result = match worker {
                PreparedSocketWorker::Receiver(PreparedSocketReceiver::Tcp(listener, config)) => {
                    run_authorized_tcp_receiver(listener, config)
                        .await
                        .and_then(|result| receiver_result_json("tcp", &result))
                }
                PreparedSocketWorker::Receiver(PreparedSocketReceiver::Udp(socket, config)) => {
                    run_udp_receiver(&socket, config)
                        .await
                        .and_then(|result| receiver_result_json("udp", &result))
                }
                PreparedSocketWorker::Sender(PreparedSocketSender::Tcp(config, destination)) => {
                    run_authorized_tcp_sender(destination, config)
                        .await
                        .and_then(|result| sender_result_json("tcp", &result))
                }
                PreparedSocketWorker::Sender(PreparedSocketSender::Udp(
                    socket,
                    config,
                    destination,
                )) => run_udp_sender(&socket, destination, config)
                    .await
                    .and_then(|result| sender_result_json("udp", &result)),
                PreparedSocketWorker::Bidirectional(worker) => {
                    run_bidirectional_worker(worker).await
                }
            };
            let mut coordinator = coordinator.lock().await;
            match result {
                Ok(result_json) => {
                    if let Err(error) = coordinator.complete(session_id, result_json) {
                        eprintln!("Node receiver result completion failed: {error}");
                    }
                }
                Err(error) => {
                    let failure = serde_json::to_vec(&json!({
                        "schema_version":"1.0",
                        "outcome":"failed",
                        "error":{"code":error.code.as_str(),"message":error.message,"retryable":error.retryable}
                    }))
                    .unwrap_or_else(|_| br#"{"schema_version":"1.0","outcome":"failed"}"#.to_vec());
                    if let Err(failure_error) = coordinator.fail(session_id, failure) {
                        eprintln!("Node receiver failure finalization failed: {failure_error}");
                    }
                }
            }
        });
    }

    fn receiver_result_json<T: serde::Serialize>(
        protocol: &str,
        result: &T,
    ) -> Result<Vec<u8>, NetToolError> {
        serde_json::to_vec(&json!({
            "schema_version":"1.0",
            "outcome":"completed",
            "protocol":protocol,
            "receiver":result
        }))
        .map_err(|error| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                format!("cannot serialize Node receiver result: {error}"),
                false,
            )
        })
    }

    fn sender_result_json<T: serde::Serialize>(
        protocol: &str,
        result: &T,
    ) -> Result<Vec<u8>, NetToolError> {
        serde_json::to_vec(&json!({
            "schema_version":"1.0",
            "outcome":"completed",
            "protocol":protocol,
            "sender":result
        }))
        .map_err(|error| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                format!("cannot serialize Node sender result: {error}"),
                false,
            )
        })
    }

    async fn run_bidirectional_worker(
        worker: PreparedSocketBidirectional,
    ) -> Result<Vec<u8>, NetToolError> {
        match worker {
            PreparedSocketBidirectional::Tcp(
                listener,
                receiver_config,
                sender_config,
                destination,
            ) => {
                let (receiver, sender) = tokio::join!(
                    run_authorized_tcp_receiver(listener, receiver_config),
                    run_authorized_tcp_sender(destination, sender_config),
                );
                let receiver = receiver?;
                let sender = sender?;
                serde_json::to_vec(&json!({
                    "schema_version":"1.0",
                    "outcome":"completed",
                    "protocol":"tcp",
                    "direction":"bidirectional",
                    "sender":sender,
                    "receiver":receiver
                }))
                .map_err(|error| {
                    NetToolError::new(
                        ErrorCode::ProtocolInvalid,
                        format!("cannot serialize TCP bidirectional result: {error}"),
                        false,
                    )
                })
            }
            PreparedSocketBidirectional::Udp(
                socket,
                receiver_config,
                sender_config,
                destination,
            ) => {
                let (receiver, sender) = tokio::join!(
                    run_udp_receiver(&socket, receiver_config),
                    run_udp_sender(&socket, destination, sender_config),
                );
                let receiver = receiver?;
                let sender = sender?;
                serde_json::to_vec(&json!({
                    "schema_version":"1.0",
                    "outcome":"completed",
                    "protocol":"udp",
                    "direction":"bidirectional",
                    "sender":sender,
                    "receiver":receiver
                }))
                .map_err(|error| {
                    NetToolError::new(
                        ErrorCode::ProtocolInvalid,
                        format!("cannot serialize UDP bidirectional result: {error}"),
                        false,
                    )
                })
            }
        }
    }

    fn parse_wire_session_id(value: &[u8]) -> Result<[u8; 16], NetToolError> {
        let session_id: [u8; 16] = value.try_into().map_err(|_| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                "scheduled session ID is invalid",
                false,
            )
        })?;
        if session_id == [0; 16] {
            return Err(NetToolError::new(
                ErrorCode::ProtocolInvalid,
                "scheduled session ID must not be zero",
                false,
            ));
        }
        Ok(session_id)
    }

    fn parse_hex_session_id(value: &str) -> Result<[u8; 16], NetToolError> {
        if value.len() != 32 {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "speed session ID must be 32 hexadecimal characters",
                false,
            ));
        }
        let mut session_id = [0_u8; 16];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(chunk).map_err(|_| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "speed session ID contains invalid text",
                    false,
                )
            })?;
            session_id[index] = u8::from_str_radix(text, 16).map_err(|_| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "speed session ID must be hexadecimal",
                    false,
                )
            })?;
        }
        if session_id == [0; 16] {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "speed session ID must not be zero",
                false,
            ));
        }
        Ok(session_id)
    }

    fn peer_fingerprint(stream: &TlsStream<TcpStream>) -> Result<String, String> {
        let certificate = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or_else(|| "Node peer did not present a certificate".to_owned())?;
        certificate_public_key_fingerprint(certificate.as_ref()).map_err(|error| error.to_string())
    }

    fn now_unix_nanoseconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
            .unwrap_or(0)
    }

    fn load_platform_identity() -> Result<(IdentityMaterial, LocalNodeIdentity), String> {
        let node_name =
            std::env::var("NETTOOL_NODE_NAME").unwrap_or_else(|_| "localhost".to_owned());
        let store = PlatformKeyringStore::open().map_err(|error| error.to_string())?;
        let provider = IdentityProvider::new(store, vec![node_name.clone()])
            .map_err(|error| error.to_string())?;
        let material = provider
            .load_or_create()
            .map_err(|error| error.to_string())?;
        let local = LocalNodeIdentity {
            node_id: material.node_id,
            name: node_name,
        };
        Ok((material, local))
    }

    fn hex_node_id(node_id: [u8; 16]) -> String {
        use std::fmt::Write as _;

        let mut value = String::with_capacity(32);
        for byte in node_id {
            // 寫入 String 不會發生 fmt I/O 錯誤。
            let _ = write!(&mut value, "{byte:02x}");
        }
        value
    }

    #[cfg(unix)]
    fn prepare_socket(path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create socket directory: {error}"))?;
        }
        if path.exists() {
            fs::remove_file(path)
                .map_err(|error| format!("cannot remove stale socket: {error}"))?;
        }
        Ok(())
    }

    fn database_path() -> PathBuf {
        if let Some(path) = std::env::var_os("NETTOOL_DATABASE") {
            return PathBuf::from(path);
        }
        if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(data).join("nettool/nettool.db");
        }
        std::env::temp_dir().join("nettool/nettool.db")
    }

    async fn handle_client<S>(mut stream: S, runtime: &AgentRuntime) -> Result<(), String>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let length = stream.read_u32().await.map_err(|error| error.to_string())? as usize;
        if length > MAX_FRAME_BYTES {
            return Err("request exceeds maximum frame size".to_owned());
        }
        let mut payload = vec![0_u8; length];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|error| error.to_string())?;
        let request = decode_payload(&payload)?;
        let response = action_dispatch::dispatch(request, runtime).await;
        stream
            .write_all(&encode_frame(&response)?)
            .await
            .map_err(|error| error.to_string())
    }

    fn is_helper_action(action: &str) -> bool {
        matches!(
            action,
            "profile.apply"
                | "profile.confirm"
                | "profile.rollback"
                | "ip.set"
                | "ip.dhcp"
                | "dns.set"
                | "hosts.replace"
                | "hosts.add"
                | "hosts.remove"
                | "hosts.enable"
                | "hosts.disable"
                | "hosts.backup"
                | "hosts.restore"
                | "hosts.read"
        )
    }

    fn dry_run_plan(action: &str, payload: &[u8], operation_id: &str) -> ActionResponse {
        let Some(descriptor) = ActionRegistry::find(action) else {
            return failure("ACTION.UNKNOWN", "action is not registered", false);
        };
        if let Err(error) = validate_dry_run_payload(action, payload) {
            return failure(error.code.as_str(), &error.message, error.retryable);
        }
        let digest = Sha256::digest(payload);
        let value = json!({
            "schema_version": "1.0",
            "dry_run": true,
            "action": action,
            "operation_id": operation_id,
            "permission": permission_name(descriptor.permission),
            "idempotent": descriptor.idempotent,
            "payload_sha256": format!("{digest:x}"),
            "side_effects": "not executed"
        });
        ActionResponse {
            success: true,
            data_json: serde_json::to_vec(&value).unwrap_or_default(),
            error_code: String::new(),
            error_message: String::new(),
            retryable: false,
        }
    }

    const fn permission_name(permission: PermissionRequirement) -> &'static str {
        match permission {
            PermissionRequirement::ReadOnly => "read_only",
            PermissionRequirement::User => "user",
            PermissionRequirement::Privileged => "privileged",
        }
    }

    /// 在不讀取外部檔案或建立資源的前提下驗證 dry-run payload 形狀。
    #[allow(clippy::too_many_lines)]
    fn validate_dry_run_payload(action: &str, payload: &[u8]) -> Result<(), NetToolError> {
        let value: serde_json::Value = serde_json::from_slice(payload).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("dry-run payload is not valid JSON: {error}"),
                false,
            )
        })?;
        if !value.is_object() {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "dry-run payload must be a JSON object",
                false,
            ));
        }
        match action {
            "speed.run" => {
                let request = parse_speed_payload(payload)?;
                request.validate()?;
                validate_socket_speed_options(&request)
            }
            "perf.benchmark" => action_perf::validate_benchmark_payload(payload),
            "speed.cancel" => {
                serde_json::from_slice::<action_speed::CancelPayload>(payload).map_err(
                    |error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid speed cancel dry-run payload: {error}"),
                            false,
                        )
                    },
                )?;
                Ok(())
            }
            "interface.show" => action_persistent::parse_interface_target(payload).map(|_| ()),
            "profile.show" | "profile.export" | "profile.delete" | "node.revoke" => {
                action_profile::parse_profile_target(payload).map(|_| ())
            }
            "packet.analyze" => {
                serde_json::from_slice::<action_packet::PacketAnalyzePayload>(payload).map_err(
                    |error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid packet analyze dry-run payload: {error}"),
                            false,
                        )
                    },
                )?;
                Ok(())
            }
            "packet.capture.stop" => {
                serde_json::from_slice::<action_packet::PacketCaptureStopPayload>(payload)
                    .map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid packet capture stop dry-run payload: {error}"),
                            false,
                        )
                    })?;
                Ok(())
            }
            "profile.create" => {
                serde_json::from_slice::<action_profile::ProfileCreatePayload>(payload).map_err(
                    |error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid profile create dry-run payload: {error}"),
                            false,
                        )
                    },
                )?;
                Ok(())
            }
            "profile.edit" => {
                serde_json::from_slice::<action_profile::ProfileEditPayload>(payload).map_err(
                    |error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid profile edit dry-run payload: {error}"),
                            false,
                        )
                    },
                )?;
                Ok(())
            }
            "profile.import" => {
                serde_json::from_slice::<action_profile::ProfileImportPayload>(payload).map_err(
                    |error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid profile import dry-run payload: {error}"),
                            false,
                        )
                    },
                )?;
                Ok(())
            }
            "node.pair" => {
                serde_json::from_slice::<action_node::NodePairPayload>(payload).map_err(
                    |error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid node pair dry-run payload: {error}"),
                            false,
                        )
                    },
                )?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn storage_error(message: String) -> NetToolError {
        NetToolError::new(ErrorCode::StorageFailed, message, false)
    }

    fn parse_speed_payload(payload: &[u8]) -> Result<SpeedRunRequest, NetToolError> {
        serde_json::from_slice(payload).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("invalid speed run payload: {error}"),
                false,
            )
        })
    }

    fn validate_socket_speed_options(request: &SpeedRunRequest) -> Result<(), NetToolError> {
        if request.auto_tune || request.latency_under_load {
            return Err(NetToolError::new(
                ErrorCode::ActionUnsupported,
                "socket speed executor does not implement auto-tune or latency-under-load",
                false,
            ));
        }
        Ok(())
    }

    fn validate_accelerated_backend(request: &SpeedRunRequest) -> Result<(), NetToolError> {
        match request.backend.as_str() {
            "dpdk" => {
                if !nettool_backend_dpdk::is_backend_built() {
                    return Err(NetToolError::new(
                        ErrorCode::BackendNotBuilt,
                        "speed request is valid, but native DPDK is not linked in this build",
                        false,
                    ));
                }
                Err(NetToolError::new(
                    ErrorCode::ActionUnsupported,
                    "native DPDK speed orchestration is not attached to the Agent runtime",
                    false,
                ))
            }
            "af_xdp" => {
                let report = probe_environment()?;
                if !nettool_backend_af_xdp::is_backend_built()
                    || report.platform != nettool_domain::Platform::Linux
                    || !report.af_xdp_capable
                    || !report.af_xdp_zero_copy_capable
                {
                    return Err(NetToolError::new(
                        ErrorCode::BackendNotBuilt,
                        "AF_XDP requires a linked Linux implementation and verified zero-copy runtime capability",
                        false,
                    ));
                }
                Err(NetToolError::new(
                    ErrorCode::ActionUnsupported,
                    "AF_XDP speed orchestration is not attached to the Agent runtime",
                    false,
                ))
            }
            "rio" => {
                if !cfg!(target_os = "windows") || !nettool_backend_rio::is_backend_built() {
                    return Err(NetToolError::new(
                        ErrorCode::BackendNotBuilt,
                        "RIO requires a linked Windows Registered I/O implementation",
                        false,
                    ));
                }
                Err(NetToolError::new(
                    ErrorCode::ActionUnsupported,
                    "RIO speed orchestration is not attached to the Agent runtime",
                    false,
                ))
            }
            _ => Ok(()),
        }
    }

    fn failure(code: &str, message: &str, retryable: bool) -> ActionResponse {
        ActionResponse {
            success: false,
            data_json: Vec::new(),
            error_code: code.to_owned(),
            error_message: message.to_owned(),
            retryable,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::action_dispatch::execute_with_runtime;
        use super::action_hosts::parse_managed_hosts;
        #[cfg(target_os = "linux")]
        use super::action_packet::execute_packet_stats;
        use super::action_perf::execute as execute_perf;
        use super::action_speed::validate_request as validate_speed_request;
        use super::{AgentRuntime, handle_node_connection, hex_node_id};
        use nettool_error::NetToolError;
        use nettool_identity::{IdentityProvider, SecureSecretStore};
        use nettool_node::{
            LocalNodeIdentity, SessionCoordinator, certificate_public_key_fingerprint,
            tls13_server_config,
        };
        use nettool_storage::{Storage, TrustedNodeConnection, TrustedNodeSummary};
        use rustls::RootCertStore;
        use std::cell::RefCell;
        use std::sync::Arc;
        use tokio::net::TcpListener;
        use tokio::sync::Mutex;
        use tokio_rustls::TlsAcceptor;

        #[derive(Default)]
        struct MemoryStore(RefCell<Option<Vec<u8>>>);

        impl SecureSecretStore for MemoryStore {
            fn get_secret(&self) -> Result<Option<Vec<u8>>, NetToolError> {
                Ok(self.0.borrow().clone())
            }

            fn set_secret(&self, secret: &[u8]) -> Result<(), NetToolError> {
                *self.0.borrow_mut() = Some(secret.to_vec());
                Ok(())
            }
        }

        fn identity(name: &str) -> nettool_identity::IdentityMaterial {
            IdentityProvider::new(MemoryStore::default(), vec![name.to_owned()])
                .expect("provider")
                .load_or_create()
                .expect("identity")
        }

        #[test]
        fn backend_discovery_never_claims_unlinked_accelerated_backend() {
            let response =
                super::action_dispatch::result_response(execute_perf("perf.backend", b"{}"));
            assert!(response.success);
            let value: serde_json::Value =
                serde_json::from_slice(&response.data_json).expect("JSON");
            let backends = value["backends"].as_array().expect("backends");
            assert_eq!(backends[0]["id"], "pcap");
            assert_eq!(backends[0]["available"], true);
            let af_xdp = &backends[1];
            assert_eq!(af_xdp["id"], "af_xdp");
            assert_eq!(
                af_xdp["implementation_available"],
                nettool_backend_af_xdp::is_backend_built()
            );
            assert_eq!(
                af_xdp["available"],
                af_xdp["platform_capable"].as_bool().unwrap_or(false)
                    && nettool_backend_af_xdp::is_backend_built()
            );
            let dpdk = &backends[2];
            assert_eq!(dpdk["available"], false);
            assert_eq!(
                dpdk["implementation_available"],
                nettool_backend_dpdk::is_backend_built()
            );
            let rio = &backends[3];
            assert_eq!(rio["available"], false);
            assert_eq!(
                rio["implementation_available"],
                nettool_backend_rio::is_backend_built()
            );
        }

        #[test]
        fn dry_run_plan_never_executes_action_payload() {
            let response = super::dry_run_plan(
                "speed.run",
                br#"{"node":"remote","protocol":"tcp","backend":"socket","direction":"upload","duration_ms":1000,"warmup_ms":0,"cooldown_ms":0,"streams":1,"frame_size":null,"target_rate_bps":null,"auto_tune":false,"latency_under_load":false,"cpus":null,"numa_node":null}"#,
                "operation-1",
            );
            assert!(response.success);
            let value: serde_json::Value =
                serde_json::from_slice(&response.data_json).expect("dry-run JSON");
            assert_eq!(value["dry_run"], true);
            assert_eq!(value["action"], "speed.run");
            assert_eq!(value["operation_id"], "operation-1");
            assert_eq!(value["permission"], "user");
            assert_eq!(value["side_effects"], "not executed");
            assert!(
                value["payload_sha256"]
                    .as_str()
                    .is_some_and(|hash| hash.len() == 64)
            );
        }

        #[test]
        fn dry_run_rejects_malformed_speed_payload() {
            let response = super::dry_run_plan("speed.run", br#"{"backend":"socket"}"#, "op");
            assert!(!response.success);
            assert_eq!(response.error_code, "CLI.INVALID_ARGUMENT");
        }

        #[test]
        fn dry_run_validates_benchmark_profile_without_running_hardware() {
            let response = super::dry_run_plan("perf.benchmark", br#"{"profile":"missing"}"#, "op");
            assert!(!response.success);
            assert_eq!(response.error_code, "CLI.INVALID_ARGUMENT");
        }

        #[test]
        fn accelerated_speed_never_falls_back_to_socket_executor() {
            let request: super::SpeedRunRequest = serde_json::from_slice(
                br#"{"node":"node-b","protocol":"tcp","backend":"native","direction":"upload","duration_ms":1000,"warmup_ms":0,"cooldown_ms":0,"streams":1,"frame_size":null,"target_rate_bps":null,"auto_tune":false,"latency_under_load":false,"cpus":null,"numa_node":null}"#,
            )
            .expect("speed request");
            super::validate_accelerated_backend(&request).expect("native socket backend");

            let mut accelerated = request;
            accelerated.backend = "dpdk".to_owned();
            let result = super::validate_accelerated_backend(&accelerated);
            assert!(matches!(
                result,
                Err(error)
                    if error.code.as_str() == "DATAPLANE.BACKEND_NOT_BUILT"
                        || error.code.as_str() == "ACTION.UNSUPPORTED"
            ));
        }

        #[test]
        fn benchmark_profile_is_validated_before_backend_failure() {
            let unknown = execute_perf("perf.benchmark", br#"{"profile":"missing"}"#);
            assert!(matches!(unknown, Err(error) if error.code.as_str() == "CLI.INVALID_ARGUMENT"));
            let known = execute_perf("perf.benchmark", br#"{"profile":"100g-cert"}"#);
            assert!(
                matches!(known, Err(error) if error.code.as_str() == "DATAPLANE.BACKEND_NOT_BUILT")
            );
        }

        #[test]
        fn managed_hosts_parser_is_scoped_to_one_profile() {
            let content = concat!(
                "127.0.0.1 localhost\n",
                "# BEGIN NETTOOL PROFILE lab\n",
                "192.0.2.10 api.lab # managed\n",
                "# NETTOOL DISABLED 2001:db8::10 v6.lab\n",
                "# END NETTOOL PROFILE lab\n",
                "203.0.113.4 user.entry\n"
            );
            let entries = parse_managed_hosts(content, "lab").expect("managed section");
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].hostname, "api.lab");
            assert_eq!(entries[0].comment.as_deref(), Some("managed"));
            assert_eq!(entries[1].address, "2001:db8::10");
            assert!(!entries[1].enabled);
            assert!(
                parse_managed_hosts(content, "missing")
                    .expect("missing section")
                    .is_empty()
            );
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn packet_stats_reads_kernel_loopback_counters() {
            let payload = br#"{"interface_id":"lo"}"#;
            let value = execute_packet_stats(payload).expect("loopback sysfs counters");
            assert_eq!(value["platform"], "linux");
            assert_eq!(value["interfaces"][0]["interface"], "lo");
            assert!(value["interfaces"][0]["rx_packets"].is_number());
            assert!(value["interfaces"][0]["tx_dropped"].is_number());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn packet_connections_reads_procfs_endpoint_tables() {
            let value = execute_packet_connections(br#"{"protocol":"tcp"}"#)
                .expect("procfs connection tables");
            assert_eq!(value["platform"], "linux");
            assert!(value["connections"].is_array());
            assert_eq!(value["source"], "procfs");
        }

        #[test]
        fn speed_run_validates_contract_before_trusted_node_lookup() {
            let storage = Storage::in_memory().expect("storage");
            let invalid = validate_speed_request(
                br#"{"node":"node-b","protocol":"raw","backend":"socket","direction":"upload","duration_ms":10000,"warmup_ms":1000,"cooldown_ms":1000,"streams":null,"frame_size":64,"target_rate_bps":100000000000,"auto_tune":false,"latency_under_load":false,"cpus":null,"numa_node":null}"#,
                &storage,
            );
            assert_eq!(
                invalid.expect_err("invalid contract").code.as_str(),
                "CLI.INVALID_ARGUMENT"
            );
            let valid = validate_speed_request(
                br#"{"node":"node-b","protocol":"raw","backend":"dpdk","direction":"upload","duration_ms":10000,"warmup_ms":1000,"cooldown_ms":1000,"streams":null,"frame_size":64,"target_rate_bps":100000000000,"auto_tune":false,"latency_under_load":false,"cpus":null,"numa_node":null}"#,
                &storage,
            );
            assert_eq!(
                valid.expect_err("unpaired node").code.as_str(),
                "NODE.NOT_PAIRED"
            );
        }

        #[tokio::test]
        #[ignore = "requires permission to bind a loopback TCP socket"]
        #[allow(clippy::too_many_lines)]
        async fn speed_runtime_performs_mutual_tls_and_tcp_download() {
            let local_material = identity("localhost");
            let remote_material = identity("localhost");
            let remote_node_id = remote_material.node_id;
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
            let address = listener.local_addr().expect("address");
            let mut client_roots = RootCertStore::empty();
            client_roots
                .add(local_material.certificate_chain[0].clone())
                .expect("client root");
            let server_config = tls13_server_config(
                remote_material.certificate_chain.clone(),
                remote_material.private_key.clone_key(),
                client_roots,
            )
            .expect("server TLS");
            let local_certificate = local_material.certificate_chain[0].clone();
            let local_fingerprint = certificate_public_key_fingerprint(local_certificate.as_ref())
                .expect("fingerprint");
            let local_id = hex_node_id(local_material.node_id);
            let trusted_client = TrustedNodeSummary {
                id: local_id,
                name: "local".to_owned(),
                last_address: None,
                fingerprint: local_fingerprint,
                certificate_der: local_certificate.as_ref().to_vec(),
                server_name: "localhost".to_owned(),
                control_address: "127.0.0.1:1".to_owned(),
            };
            let server = tokio::spawn(async move {
                let (stream, peer_address) = listener.accept().await.expect("accept");
                handle_node_connection(
                    stream,
                    peer_address,
                    TlsAcceptor::from(Arc::new(server_config)),
                    vec![trusted_client],
                    LocalNodeIdentity {
                        node_id: remote_node_id,
                        name: "remote".to_owned(),
                    },
                    Arc::new(Mutex::new(SessionCoordinator::new())),
                )
                .await
            });
            let mut storage = Storage::in_memory().expect("storage");
            let remote_certificate = remote_material.certificate_chain[0].clone();
            let fingerprint = certificate_public_key_fingerprint(remote_certificate.as_ref())
                .expect("fingerprint");
            let remote_id = hex_node_id(remote_node_id);
            storage
                .trust_node_connection(&TrustedNodeConnection {
                    node_id: &remote_id,
                    name: "remote",
                    control_address: &address.to_string(),
                    server_name: "localhost",
                    certificate_der: remote_certificate.as_ref(),
                    fingerprint: &fingerprint,
                    out_of_band_fingerprint_confirmed: true,
                    identity_change_confirmed: false,
                })
                .expect("trust");
            let local_node_id = local_material.node_id;
            let runtime = AgentRuntime {
                storage: Arc::new(Mutex::new(storage)),
                identity_material: local_material,
                local_identity: LocalNodeIdentity {
                    node_id: local_node_id,
                    name: "local".to_owned(),
                },
                node_coordinator: Arc::new(Mutex::new(SessionCoordinator::new())),
                capture_children: Arc::new(Mutex::new(std::collections::HashMap::new())),
            };
            let response = execute_with_runtime(
                "speed.run",
                br#"{"node":"remote","protocol":"tcp","backend":"socket","direction":"download","duration_ms":100,"warmup_ms":0,"cooldown_ms":0,"streams":1,"frame_size":null,"target_rate_bps":null,"auto_tune":false,"latency_under_load":false,"cpus":null,"numa_node":null}"#,
                "speed-test",
                false,
                &runtime,
            )
            .await;
            assert!(
                response.success,
                "{}: {}",
                response.error_code, response.error_message
            );
            let result: serde_json::Value =
                serde_json::from_slice(&response.data_json).expect("speed result JSON");
            assert_eq!(result["sender"]["outcome"], "completed");
            assert!(
                result["sender"]["sender"]["transferred_bytes"]
                    .as_u64()
                    .unwrap_or(0)
                    > 0
            );
            assert!(
                result["receiver"]["transferred_bytes"]
                    .as_u64()
                    .unwrap_or(0)
                    > 0
            );
            let session_id = result["session_id"].as_str().expect("session ID");
            assert_eq!(
                runtime
                    .storage
                    .lock()
                    .await
                    .speed_session_state(session_id)
                    .expect("session state"),
                Some("completed".to_owned())
            );
            assert!(server.await.expect("server task").is_err());
        }
    }
}

#[cfg(any(unix, windows))]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match agent_runtime::run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
