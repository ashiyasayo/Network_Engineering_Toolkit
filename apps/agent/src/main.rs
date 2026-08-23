//! `NetTool` 唯一 runtime authority 的本機 IPC 入口。

#![forbid(unsafe_code)]

#[cfg(any(unix, windows))]
mod agent_runtime {
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
                eprintln!("agent client error: {error}");
            }
        });
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
                        eprintln!("Node control accept failed: {error}");
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
                        eprintln!("Node control connection failed: {error}");
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
        let response = dispatch(request, runtime).await;
        stream
            .write_all(&encode_frame(&response)?)
            .await
            .map_err(|error| error.to_string())
    }

    async fn dispatch(envelope: AgentEnvelope, runtime: &AgentRuntime) -> AgentEnvelope {
        let request_id = envelope.request_id;
        let response = match envelope.payload {
            Some(agent_envelope::Payload::Request(request)) => {
                execute_with_runtime(
                    &request.action,
                    &request.payload_json,
                    &request.operation_id,
                    request.dry_run,
                    runtime,
                )
                .await
            }
            _ => failure("AGENT.INVALID_MESSAGE", "expected action request", false),
        };
        AgentEnvelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id,
            payload: Some(agent_envelope::Payload::Response(response)),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_with_runtime(
        action: &str,
        payload: &[u8],
        operation_id: &str,
        dry_run: bool,
        runtime: &AgentRuntime,
    ) -> ActionResponse {
        if dry_run && !is_helper_action(action) {
            return dry_run_plan(action, payload, operation_id);
        }
        if action == "speed.cancel" {
            return match execute_cancel(payload, runtime).await {
                Ok(value) => ActionResponse {
                    success: true,
                    data_json: serde_json::to_vec(&value).unwrap_or_default(),
                    error_code: String::new(),
                    error_message: String::new(),
                    retryable: false,
                },
                Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
            };
        }
        if action == "packet.analyze" {
            let result = execute_packet_analyze(payload).await;
            return match result {
                Ok(value) => ActionResponse {
                    success: true,
                    data_json: serde_json::to_vec(&value).unwrap_or_default(),
                    error_code: String::new(),
                    error_message: String::new(),
                    retryable: false,
                },
                Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
            };
        }
        if matches!(action, "packet.capture.start" | "packet.capture.stop") {
            let result = execute_packet_capture(action, payload, runtime).await;
            return match result {
                Ok(value) => ActionResponse {
                    success: true,
                    data_json: serde_json::to_vec(&value).unwrap_or_default(),
                    error_code: String::new(),
                    error_message: String::new(),
                    retryable: false,
                },
                Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
            };
        }
        if action == "packet.stats" {
            let result = execute_packet_stats(payload);
            return match result {
                Ok(value) => ActionResponse {
                    success: true,
                    data_json: serde_json::to_vec(&value).unwrap_or_default(),
                    error_code: String::new(),
                    error_message: String::new(),
                    retryable: false,
                },
                Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
            };
        }
        if action == "packet.connections" {
            let result = execute_packet_connections(payload);
            return match result {
                Ok(value) => ActionResponse {
                    success: true,
                    data_json: serde_json::to_vec(&value).unwrap_or_default(),
                    error_code: String::new(),
                    error_message: String::new(),
                    retryable: false,
                },
                Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
            };
        }
        if matches!(
            action,
            "profile.create"
                | "profile.edit"
                | "profile.delete"
                | "profile.import"
                | "node.pair"
                | "node.revoke"
        ) {
            let result = {
                let mut storage = runtime.storage.lock().await;
                execute_profile_mutation(action, payload, &mut storage)
            };
            return match result {
                Ok(value) => ActionResponse {
                    success: true,
                    data_json: serde_json::to_vec(&value).unwrap_or_default(),
                    error_code: String::new(),
                    error_message: String::new(),
                    retryable: false,
                },
                Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
            };
        }
        if matches!(
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
        ) {
            let result =
                execute_helper_action(action, payload, operation_id, dry_run, runtime).await;
            return match result {
                Ok(value) => ActionResponse {
                    success: true,
                    data_json: serde_json::to_vec(&value).unwrap_or_default(),
                    error_code: String::new(),
                    error_message: String::new(),
                    retryable: false,
                },
                Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
            };
        }
        if action != "speed.run" {
            let storage = runtime.storage.lock().await;
            return execute(action, payload, &storage);
        }
        let result = execute_speed(payload, runtime).await;
        match result {
            Ok(value) => ActionResponse {
                success: true,
                data_json: serde_json::to_vec(&value).unwrap_or_default(),
                error_code: String::new(),
                error_message: String::new(),
                retryable: false,
            },
            Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
        }
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
            "perf.benchmark" => {
                let request = parse_benchmark_payload(payload)?;
                let profile = BenchmarkProfileRegistry::get(&request.profile).ok_or_else(|| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "benchmark profile does not exist",
                        false,
                    )
                })?;
                profile.plan.validate()
            }
            "speed.cancel" => {
                serde_json::from_slice::<CancelPayload>(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid speed cancel dry-run payload: {error}"),
                        false,
                    )
                })?;
                Ok(())
            }
            "interface.show" => parse_interface_target(payload).map(|_| ()),
            "profile.show" | "profile.export" | "profile.delete" | "node.revoke" => {
                parse_profile_target(payload).map(|_| ())
            }
            "packet.analyze" => {
                serde_json::from_slice::<PacketAnalyzePayload>(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid packet analyze dry-run payload: {error}"),
                        false,
                    )
                })?;
                Ok(())
            }
            "packet.capture.stop" => {
                serde_json::from_slice::<PacketCaptureStopPayload>(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid packet capture stop dry-run payload: {error}"),
                        false,
                    )
                })?;
                Ok(())
            }
            "profile.create" => {
                serde_json::from_slice::<ProfileCreatePayload>(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid profile create dry-run payload: {error}"),
                        false,
                    )
                })?;
                Ok(())
            }
            "profile.edit" => {
                serde_json::from_slice::<ProfileEditPayload>(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid profile edit dry-run payload: {error}"),
                        false,
                    )
                })?;
                Ok(())
            }
            "profile.import" => {
                serde_json::from_slice::<ProfileImportPayload>(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid profile import dry-run payload: {error}"),
                        false,
                    )
                })?;
                Ok(())
            }
            "node.pair" => {
                serde_json::from_slice::<NodePairPayload>(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid node pair dry-run payload: {error}"),
                        false,
                    )
                })?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn execute_cancel(
        payload: &[u8],
        runtime: &AgentRuntime,
    ) -> Result<serde_json::Value, NetToolError> {
        let request: CancelPayload = serde_json::from_slice(payload).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("invalid speed cancel payload: {error}"),
                false,
            )
        })?;
        let session_id = parse_hex_session_id(&request.session_id)?;
        let local_state = runtime
            .storage
            .lock()
            .await
            .speed_session_state(&request.session_id)?;
        if local_state.as_deref() == Some("canceled") {
            return Ok(json!({
                "schema_version":"1.0",
                "session_id":request.session_id,
                "state":"CANCELED"
            }));
        }
        if local_state.as_deref() == Some("completed") {
            return Err(NetToolError::new(
                ErrorCode::InvalidState,
                "completed speed session cannot be canceled",
                false,
            ));
        }
        let remote_id = runtime
            .storage
            .lock()
            .await
            .speed_session_remote_node(&request.session_id)?
            .ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "speed session does not exist",
                    false,
                )
            })?;
        let node = runtime
            .storage
            .lock()
            .await
            .resolve_trusted_node(&remote_id)?
            .ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::NodeNotPaired,
                    "speed session remote Node is no longer trusted",
                    false,
                )
            })?;
        let (endpoint, tls) = trusted_connection_config(node, runtime)?;
        let mut client = connect_control_client(&endpoint, tls, &runtime.local_identity).await?;
        let status = client
            .stop_test(StopTest {
                session_id: session_id.to_vec(),
                operation_id: format!("cancel-{}", request.session_id),
            })
            .await?;
        if status.session_id.as_slice() != session_id || status.state != "CANCELED" {
            return Err(NetToolError::new(
                ErrorCode::InvalidState,
                "remote Node did not confirm CANCELED state",
                false,
            ));
        }
        let detail = json!({"reason":"user_cancel"});
        runtime.storage.lock().await.terminate_speed_session(
            &request.session_id,
            &utc_timestamp(),
            "canceled",
            &detail,
        )?;
        Ok(json!({
            "schema_version":"1.0",
            "session_id":request.session_id,
            "state":"CANCELED"
        }))
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PacketAnalyzePayload {
        input: String,
        sample_one_in: Option<u32>,
    }

    async fn execute_packet_analyze(payload: &[u8]) -> Result<serde_json::Value, NetToolError> {
        let request: PacketAnalyzePayload = serde_json::from_slice(payload).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("invalid packet analyze payload: {error}"),
                false,
            )
        })?;
        if request.input.trim().is_empty() {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "packet capture input must not be empty",
                false,
            ));
        }
        if request.sample_one_in == Some(0) {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "sample ratio must be greater than zero",
                false,
            ));
        }
        tokio::task::spawn_blocking(move || {
            let coverage = request
                .sample_one_in
                .map_or(AnalysisCoverage::Full, |one_in| AnalysisCoverage::Sampled {
                    one_in,
                });
            let mut source = CaptureFileSource::open(&request.input)?;
            let mut worker = PacketWorker::new(
                PacketWorkerConfiguration {
                    maximum_flows: 1_000_000,
                    flow_idle_timeout_nanoseconds: 60_000_000_000,
                    analysis_coverage: coverage,
                },
                None,
            )?;
            let result = worker.run_bursts(&mut source, u64::MAX, &StopToken::new())?;
            let coverage = match result.analysis_coverage {
                AnalysisCoverage::Full => json!({"coverage":"full","sample_one_in":null}),
                AnalysisCoverage::Sampled { one_in } => {
                    json!({"coverage":"sampled","sample_one_in":one_in})
                }
            };
            Ok(json!({
                "schema_version": "1.0",
                "backend": "offline_capture",
                "input": request.input,
                "bursts": result.bursts,
                "analysis": coverage,
                "statistics": result.statistics,
            }))
        })
        .await
        .map_err(|error| {
            NetToolError::new(
                ErrorCode::ActionUnsupported,
                format!("packet analysis worker failed: {error}"),
                false,
            )
        })?
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PacketStatsPayload {
        interface_id: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PacketCaptureStartPayload {
        interface: String,
        output: String,
        bursts: u64,
        #[serde(default = "default_capture_backend")]
        backend: String,
        #[serde(default)]
        protocol: Option<String>,
        #[serde(default)]
        source_ip: Option<String>,
        #[serde(default)]
        destination_ip: Option<String>,
        #[serde(default)]
        source_port: Option<u16>,
        #[serde(default)]
        destination_port: Option<u16>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PacketCaptureStopPayload {
        session_id: String,
    }

    fn default_capture_backend() -> String {
        "dpdk".to_owned()
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_packet_capture(
        action: &str,
        payload: &[u8],
        runtime: &AgentRuntime,
    ) -> Result<serde_json::Value, NetToolError> {
        if action == "packet.capture.stop" {
            let request: PacketCaptureStopPayload =
                serde_json::from_slice(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid packet capture stop payload: {error}"),
                        false,
                    )
                })?;
            let _ = parse_hex_session_id(&request.session_id)?;
            let mut children = runtime.capture_children.lock().await;
            let Some(mut child) = children.remove(&request.session_id) else {
                let state = runtime
                    .storage
                    .lock()
                    .await
                    .packet_session_state(&request.session_id)?;
                return match state.as_deref() {
                    Some("completed") => Ok(
                        json!({"schema_version":"1.0","session_id":request.session_id,"state":"COMPLETED"}),
                    ),
                    Some("running") => Err(NetToolError::new(
                        ErrorCode::InvalidState,
                        "capture process is not owned by this Agent",
                        false,
                    )),
                    _ => Err(NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "packet capture session does not exist",
                        false,
                    )),
                };
            };
            child.kill().await.map_err(|error| {
                NetToolError::new(
                    ErrorCode::ActionUnsupported,
                    format!("cannot stop capture process: {error}"),
                    true,
                )
            })?;
            let _ = child.wait().await;
            runtime.storage.lock().await.complete_packet_session(
                &request.session_id,
                &utc_timestamp(),
                "canceled",
                &json!({"application":0}),
                "low",
            )?;
            return Ok(
                json!({"schema_version":"1.0","session_id":request.session_id,"state":"CANCELED"}),
            );
        }

        let request: PacketCaptureStartPayload =
            serde_json::from_slice(payload).map_err(|error| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid packet capture start payload: {error}"),
                    false,
                )
            })?;
        if request.backend != "dpdk"
            || request.interface.trim().is_empty()
            || request.output.trim().is_empty()
            || request.bursts == 0
        {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "capture requires backend dpdk, interface, output and non-zero bursts",
                false,
            ));
        }
        for (name, value) in [
            ("source IP", request.source_ip.as_deref()),
            ("destination IP", request.destination_ip.as_deref()),
        ] {
            if let Some(value) = value {
                value.parse::<std::net::IpAddr>().map_err(|_| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("{name} is invalid"),
                        false,
                    )
                })?;
            }
        }
        if let Some(protocol) = request.protocol.as_deref() {
            if !matches!(
                protocol.to_ascii_lowercase().as_str(),
                "tcp" | "udp" | "icmp" | "icmpv6"
            ) && protocol.parse::<u8>().is_err()
            {
                return Err(NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "protocol is invalid",
                    false,
                ));
            }
        }
        let session_id = hex_node_id(random_session_id()?);
        let started_at = utc_timestamp();
        runtime.storage.lock().await.begin_packet_session(
            &nettool_storage::PacketSessionPersistenceRequest {
                session_id: &session_id,
                interface: &request.interface,
                backend: &request.backend,
                capture_mode: "full_packet",
                analysis_mode: "full",
                started_at: &started_at,
            },
        )?;
        let binary =
            std::env::var_os("NETTOOL_DATAPLANE_BIN").unwrap_or_else(|| "nettool-dataplane".into());
        let mut command = TokioCommand::new(binary);
        command.args([
            "capture",
            "--backend",
            "dpdk",
            "--interface",
            request.interface.as_str(),
            "--output",
            request.output.as_str(),
            "--bursts",
        ]);
        command.arg(request.bursts.to_string());
        if let Some(protocol) = request.protocol.as_deref() {
            command.args(["--protocol", protocol]);
        }
        if let Some(source_ip) = request.source_ip.as_deref() {
            command.args(["--source-ip", source_ip]);
        }
        if let Some(destination_ip) = request.destination_ip.as_deref() {
            command.args(["--destination-ip", destination_ip]);
        }
        if let Some(source_port) = request.source_port {
            command.args(["--source-port", &source_port.to_string()]);
        }
        if let Some(destination_port) = request.destination_port {
            command.args(["--destination-port", &destination_port.to_string()]);
        }
        let child = command.spawn().map_err(|error| {
            NetToolError::new(
                ErrorCode::BackendNotBuilt,
                format!("cannot launch dataplane capture worker: {error}"),
                false,
            )
        })?;
        runtime
            .capture_children
            .lock()
            .await
            .insert(session_id.clone(), child);
        spawn_capture_reaper(
            Arc::clone(&runtime.capture_children),
            Arc::clone(&runtime.storage),
        );
        Ok(json!({
            "schema_version":"1.0",
            "session_id":session_id,
            "state":"RUNNING",
            "backend":request.backend,
            "interface":request.interface,
            "output":request.output,
            "bursts":request.bursts,
        }))
    }

    fn spawn_capture_reaper(
        children: Arc<Mutex<HashMap<String, Child>>>,
        storage: Arc<Mutex<Storage>>,
    ) {
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(100)).await;
                let mut finished = Vec::new();
                {
                    let mut children = children.lock().await;
                    for (session_id, child) in children.iter_mut() {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                finished.push((session_id.clone(), status.success()));
                            }
                            Ok(None) => {}
                            Err(_) => finished.push((session_id.clone(), false)),
                        }
                    }
                    for (session_id, _) in &finished {
                        children.remove(session_id);
                    }
                }
                if finished.is_empty() {
                    continue;
                }
                let mut storage = storage.lock().await;
                for (session_id, success) in finished {
                    let state = if success { "completed" } else { "failed" };
                    let confidence = if success { "medium" } else { "low" };
                    let _ = storage.complete_packet_session(
                        &session_id,
                        &utc_timestamp(),
                        state,
                        &json!({"application":0}),
                        confidence,
                    );
                }
            }
        });
    }

    fn execute_packet_stats(payload: &[u8]) -> Result<serde_json::Value, NetToolError> {
        if !cfg!(target_os = "linux") {
            return Err(NetToolError::new(
                ErrorCode::Unsupported,
                "packet interface statistics require Linux sysfs in this build",
                false,
            ));
        }
        let request: PacketStatsPayload = serde_json::from_slice(payload).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("invalid packet stats payload: {error}"),
                false,
            )
        })?;
        let interfaces = if let Some(interface_id) = request.interface_id {
            vec![interface_id]
        } else {
            fs::read_dir("/sys/class/net")
                .map_err(|error| {
                    NetToolError::new(
                        ErrorCode::ProbeFailed,
                        format!("cannot enumerate Linux network interfaces: {error}"),
                        true,
                    )
                })?
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect()
        };
        let mut result = Vec::with_capacity(interfaces.len());
        for interface_id in interfaces {
            if interface_id.is_empty()
                || interface_id.contains(['/', '\\'])
                || interface_id.chars().any(char::is_control)
            {
                return Err(NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "interface ID contains unsupported characters",
                    false,
                ));
            }
            let base = Path::new("/sys/class/net")
                .join(&interface_id)
                .join("statistics");
            let read_counter = |name: &str| -> Result<u64, NetToolError> {
                let path = base.join(name);
                let value = fs::read_to_string(&path).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::ProbeFailed,
                        format!("cannot read interface counter {}: {error}", path.display()),
                        true,
                    )
                })?;
                value.trim().parse::<u64>().map_err(|_| {
                    NetToolError::new(
                        ErrorCode::ProbeFailed,
                        format!("interface counter {} is invalid", path.display()),
                        false,
                    )
                })
            };
            result.push(json!({
                "interface": interface_id,
                "rx_packets": read_counter("rx_packets")?,
                "tx_packets": read_counter("tx_packets")?,
                "rx_bytes": read_counter("rx_bytes")?,
                "tx_bytes": read_counter("tx_bytes")?,
                "rx_dropped": read_counter("rx_dropped")?,
                "tx_dropped": read_counter("tx_dropped")?,
            }));
        }
        Ok(json!({"schema_version":"1.0","platform":"linux","interfaces":result}))
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PacketConnectionsPayload {
        protocol: Option<String>,
    }

    fn execute_packet_connections(payload: &[u8]) -> Result<serde_json::Value, NetToolError> {
        if !cfg!(target_os = "linux") {
            return Err(NetToolError::new(
                ErrorCode::Unsupported,
                "packet connection statistics require Linux procfs in this build",
                false,
            ));
        }
        let request: PacketConnectionsPayload =
            serde_json::from_slice(payload).map_err(|error| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid packet connections payload: {error}"),
                    false,
                )
            })?;
        let protocol = request.protocol.as_deref().map(str::to_ascii_lowercase);
        if protocol
            .as_deref()
            .is_some_and(|value| value != "tcp" && value != "udp")
        {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "packet connection protocol must be tcp or udp",
                false,
            ));
        }
        let mut connections = Vec::new();
        if protocol.as_deref().is_none_or(|value| value == "tcp") {
            parse_proc_connections("tcp", "/proc/net/tcp", &mut connections)?;
            parse_proc_connections("tcp6", "/proc/net/tcp6", &mut connections)?;
        }
        if protocol.as_deref().is_none_or(|value| value == "udp") {
            parse_proc_connections("udp", "/proc/net/udp", &mut connections)?;
            parse_proc_connections("udp6", "/proc/net/udp6", &mut connections)?;
        }
        Ok(json!({
            "schema_version":"1.0",
            "platform":"linux",
            "source":"procfs",
            "connections":connections,
            "limitations":["process and PID are not inferred when procfs does not expose inode ownership", "traffic counters are not available from /proc/net endpoint tables"]
        }))
    }

    fn parse_proc_connections(
        protocol: &str,
        path: &str,
        output: &mut Vec<serde_json::Value>,
    ) -> Result<(), NetToolError> {
        let contents = fs::read_to_string(path).map_err(|error| {
            NetToolError::new(
                ErrorCode::ProbeFailed,
                format!("cannot read {path}: {error}"),
                true,
            )
        })?;
        for line in contents.lines().skip(1) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 4 {
                continue;
            }
            let (local_address, local_port) = parse_proc_endpoint(fields[1], path)?;
            let (remote_address, remote_port) = parse_proc_endpoint(fields[2], path)?;
            let state = tcp_state(fields[3]);
            output.push(json!({
                "local_address":local_address,
                "local_port":local_port,
                "remote_address":remote_address,
                "remote_port":remote_port,
                "protocol":protocol,
                "connection_state":state,
                "process":null,
                "pid":null,
                "traffic":null
            }));
        }
        Ok(())
    }

    fn parse_proc_endpoint(value: &str, path: &str) -> Result<(String, u16), NetToolError> {
        let (address, port) = value.rsplit_once(':').ok_or_else(|| {
            NetToolError::new(
                ErrorCode::ProbeFailed,
                format!("invalid endpoint in {path}"),
                false,
            )
        })?;
        let port = u16::from_str_radix(port, 16).map_err(|_| {
            NetToolError::new(
                ErrorCode::ProbeFailed,
                format!("invalid port in {path}"),
                false,
            )
        })?;
        let address = if address.len() == 8 {
            let value = u32::from_str_radix(address, 16).map_err(|_| {
                NetToolError::new(
                    ErrorCode::ProbeFailed,
                    format!("invalid IPv4 in {path}"),
                    false,
                )
            })?;
            std::net::Ipv4Addr::from(value.swap_bytes()).to_string()
        } else if address.len() == 32 {
            let mut bytes = [0_u8; 16];
            for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16)
                    .map_err(|_| {
                        NetToolError::new(
                            ErrorCode::ProbeFailed,
                            format!("invalid IPv6 in {path}"),
                            false,
                        )
                    })?;
                bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            std::net::Ipv6Addr::from(bytes).to_string()
        } else {
            return Err(NetToolError::new(
                ErrorCode::ProbeFailed,
                format!("invalid address in {path}"),
                false,
            ));
        };
        Ok((address, port))
    }

    fn tcp_state(value: &str) -> &'static str {
        match value {
            "01" => "ESTABLISHED",
            "02" => "SYN_SENT",
            "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",
            "05" => "FIN_WAIT2",
            "06" => "TIME_WAIT",
            "07" => "CLOSE",
            "08" => "CLOSE_WAIT",
            "09" => "LAST_ACK",
            "0A" => "LISTEN",
            "0B" => "CLOSING",
            "0C" => "NEW_SYN_RECV",
            _ => "UNKNOWN",
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_speed(
        payload: &[u8],
        runtime: &AgentRuntime,
    ) -> Result<serde_json::Value, NetToolError> {
        let request = parse_speed_payload(payload)?;
        request.validate()?;
        validate_socket_speed_options(&request)?;
        let node = runtime
            .storage
            .lock()
            .await
            .resolve_trusted_node(&request.node)?
            .ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::NodeNotPaired,
                    "speed target is not a trusted paired node with TLS connection material",
                    false,
                )
            })?;
        validate_accelerated_backend(&request)?;
        let remote_node_id = node.id.clone();
        let (endpoint, tls) = trusted_connection_config(node, runtime)?;
        let mut client = connect_control_client(&endpoint, tls, &runtime.local_identity).await?;
        let LocalSpeedEndpoints {
            udp_socket,
            tcp_listener,
            source_port,
            receive_port,
        } = bind_local_speed_endpoints(&request).await?;
        if !matches!(
            request.direction,
            nettool_domain::Direction::Upload
                | nettool_domain::Direction::Download
                | nettool_domain::Direction::Bidirectional
        ) {
            return Err(NetToolError::new(
                ErrorCode::ActionUnsupported,
                "socket data-plane executor does not support this direction",
                false,
            ));
        }
        let session_id = random_session_id()?;
        let operation_id = format!("speed-{}", hex_node_id(session_id));
        let session_id_text =
            begin_speed_persistence(runtime, &request, &remote_node_id, session_id).await?;
        let prepared = prepare_remote_speed_session(
            &mut client,
            &request,
            &operation_id,
            session_id,
            LocalDataPlanePorts {
                send: source_port,
                receive: receive_port,
            },
        )
        .await;
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let detail = json!({"error": error.message.clone(), "code": error.code.as_str()});
                terminate_speed_persistence(runtime, &session_id_text, &detail).await;
                return Err(error);
            }
        };
        mark_speed_running_or_terminate(runtime, &session_id_text).await?;
        let result = if request.direction == nettool_domain::Direction::Download {
            execute_prepared_download(
                &mut client,
                &request,
                &endpoint,
                tcp_listener,
                udp_socket,
                prepared,
                &operation_id,
            )
            .await
        } else if request.direction == nettool_domain::Direction::Upload {
            execute_prepared_upload(
                &mut client,
                &request,
                &endpoint,
                udp_socket.as_ref(),
                prepared,
                &operation_id,
            )
            .await
        } else {
            execute_prepared_bidirectional(
                &mut client,
                &request,
                &endpoint,
                tcp_listener,
                udp_socket,
                prepared,
                &operation_id,
            )
            .await
        };
        persist_speed_outcome(runtime, &session_id_text, result).await
    }

    struct LocalSpeedEndpoints {
        udp_socket: Option<UdpSocket>,
        tcp_listener: Option<TcpListener>,
        source_port: u16,
        receive_port: u16,
    }

    async fn bind_local_speed_endpoints(
        request: &SpeedRunRequest,
    ) -> Result<LocalSpeedEndpoints, NetToolError> {
        let udp_socket = if request.protocol == nettool_domain::SpeedProtocol::Udp
            && matches!(
                request.direction,
                nettool_domain::Direction::Upload
                    | nettool_domain::Direction::Download
                    | nettool_domain::Direction::Bidirectional
            ) {
            // Socket 保持存活直到 capability/planner 完成，避免回收後把零或過期 port 授權給 remote。
            Some(UdpSocket::bind("0.0.0.0:0").await.map_err(|error| {
                NetToolError::new(
                    ErrorCode::SpeedFailed,
                    format!("cannot bind UDP source endpoint: {error}"),
                    true,
                )
            })?)
        } else {
            None
        };
        let tcp_listener = if request.protocol == nettool_domain::SpeedProtocol::Tcp
            && matches!(
                request.direction,
                nettool_domain::Direction::Download | nettool_domain::Direction::Bidirectional
            ) {
            Some(TcpListener::bind("0.0.0.0:0").await.map_err(|error| {
                NetToolError::new(
                    ErrorCode::SpeedFailed,
                    format!("cannot bind TCP receiver endpoint: {error}"),
                    true,
                )
            })?)
        } else {
            None
        };
        let source_port = if request.protocol == nettool_domain::SpeedProtocol::Udp
            && matches!(
                request.direction,
                nettool_domain::Direction::Upload | nettool_domain::Direction::Bidirectional
            ) {
            udp_socket
                .as_ref()
                .map_or(Ok(0), |socket| {
                    socket.local_addr().map(|address| address.port())
                })
                .map_err(|error| {
                    NetToolError::new(
                        ErrorCode::SpeedFailed,
                        format!("cannot inspect UDP source endpoint: {error}"),
                        false,
                    )
                })?
        } else {
            0
        };
        let receive_port = if request.protocol == nettool_domain::SpeedProtocol::Udp
            && matches!(
                request.direction,
                nettool_domain::Direction::Download | nettool_domain::Direction::Bidirectional
            ) {
            udp_socket
                .as_ref()
                .map_or(Ok(0), |socket| {
                    socket.local_addr().map(|address| address.port())
                })
                .map_err(|error| {
                    NetToolError::new(
                        ErrorCode::SpeedFailed,
                        format!("cannot inspect UDP receiver endpoint: {error}"),
                        false,
                    )
                })?
        } else {
            tcp_listener
                .as_ref()
                .map(|listener| listener.local_addr().map(|address| address.port()))
                .transpose()
                .map_err(|error| {
                    NetToolError::new(
                        ErrorCode::SpeedFailed,
                        format!("cannot inspect TCP receiver endpoint: {error}"),
                        false,
                    )
                })?
                .unwrap_or(0)
        };
        Ok(LocalSpeedEndpoints {
            udp_socket,
            tcp_listener,
            source_port,
            receive_port,
        })
    }

    async fn persist_speed_outcome(
        runtime: &AgentRuntime,
        session_id: &str,
        result: Result<serde_json::Value, NetToolError>,
    ) -> Result<serde_json::Value, NetToolError> {
        match result {
            Ok(value) => {
                runtime.storage.lock().await.complete_speed_session(
                    session_id,
                    &utc_timestamp(),
                    &value,
                )?;
                Ok(value)
            }
            Err(error) => {
                let detail = json!({"error": error.message.clone(), "code": error.code.as_str()});
                terminate_speed_persistence(runtime, session_id, &detail).await;
                Err(error)
            }
        }
    }

    async fn begin_speed_persistence(
        runtime: &AgentRuntime,
        request: &SpeedRunRequest,
        remote_node_id: &str,
        session_id: [u8; 16],
    ) -> Result<String, NetToolError> {
        let session_id_text = hex_node_id(session_id);
        let configuration = serde_json::to_value(request).map_err(|error| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                format!("cannot serialize speed session configuration: {error}"),
                false,
            )
        })?;
        let protocol = serde_json::to_value(request.protocol)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        let direction = serde_json::to_value(request.direction)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        let started_at = utc_timestamp();
        runtime
            .storage
            .lock()
            .await
            .begin_speed_session(&SpeedSessionPersistenceRequest {
                session_id: &session_id_text,
                remote_node_id,
                protocol: &protocol,
                backend: &request.backend,
                direction: &direction,
                started_at: &started_at,
                configuration: &configuration,
            })?;
        Ok(session_id_text)
    }

    async fn terminate_speed_persistence(
        runtime: &AgentRuntime,
        session_id: &str,
        detail: &serde_json::Value,
    ) {
        let _ = runtime.storage.lock().await.terminate_speed_session(
            session_id,
            &utc_timestamp(),
            "failed",
            detail,
        );
    }

    async fn mark_speed_running_or_terminate(
        runtime: &AgentRuntime,
        session_id: &str,
    ) -> Result<(), NetToolError> {
        if let Err(error) = runtime
            .storage
            .lock()
            .await
            .mark_speed_session_running(session_id)
        {
            let detail = json!({"error": error.message.clone(), "code": error.code.as_str()});
            terminate_speed_persistence(runtime, session_id, &detail).await;
            return Err(error);
        }
        Ok(())
    }

    fn utc_timestamp() -> String {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0_i64, |duration| {
                i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
            });
        let days = seconds.div_euclid(86_400);
        let day_seconds = seconds.rem_euclid(86_400);
        let hour = day_seconds / 3_600;
        let minute = (day_seconds % 3_600) / 60;
        let second = day_seconds % 60;
        let z = days + 719_468;
        let era = (if z >= 0 { z } else { z - 146_096 }).div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
        let mut year = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let month_part = (5 * doy + 2).div_euclid(153);
        let day = doy - (153 * month_part + 2).div_euclid(5) + 1;
        let mut month = month_part + if month_part < 10 { 3 } else { -9 };
        if month <= 2 {
            year += 1;
        }
        if month < 1 {
            month = 1;
        }
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }

    async fn execute_prepared_upload<S>(
        client: &mut nettool_node::NodeControlClient<S>,
        request: &SpeedRunRequest,
        endpoint: &TrustedNodeEndpoint,
        udp_socket: Option<&tokio::net::UdpSocket>,
        prepared: nettool_node::PreparedRemoteSpeedSession,
        operation_id: &str,
    ) -> Result<serde_json::Value, NetToolError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let start_at = now_unix_nanoseconds()
            .checked_add(200_000_000)
            .ok_or_else(|| {
                NetToolError::new(ErrorCode::SpeedFailed, "scheduled start overflow", false)
            })?;
        if let Err(error) = prepared
            .start(client, &format!("{operation_id}-start"), start_at)
            .await
        {
            let _ = prepared.stop(client, &format!("{operation_id}-stop")).await;
            return Err(error);
        }
        let now = now_unix_nanoseconds();
        if start_at > now {
            sleep(Duration::from_nanos(start_at - now)).await;
        }
        let destination = SocketAddr::new(endpoint.address.ip(), prepared.remote_data_port);
        let sender_result = run_upload_sender(request, destination, udp_socket, &prepared).await;
        let sender_result = match sender_result {
            Ok(result) => result,
            Err(error) => {
                let _ = prepared.stop(client, &format!("{operation_id}-stop")).await;
                return Err(error);
            }
        };
        let remote_result = match wait_for_remote_result(client, &prepared).await {
            Ok(result) => result,
            Err(error) => {
                let _ = prepared.stop(client, &format!("{operation_id}-stop")).await;
                return Err(error);
            }
        };
        let receiver = serde_json::from_slice::<serde_json::Value>(&remote_result.result_json)
            .map_err(|error| {
                NetToolError::new(
                    ErrorCode::ProtocolInvalid,
                    format!("remote result JSON is invalid: {error}"),
                    false,
                )
            })?;
        Ok(json!({
            "session_id": hex_node_id(prepared.session_id),
            "sender": sender_result,
            "receiver": receiver,
        }))
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_prepared_bidirectional<S>(
        client: &mut nettool_node::NodeControlClient<S>,
        request: &SpeedRunRequest,
        endpoint: &TrustedNodeEndpoint,
        tcp_listener: Option<TcpListener>,
        udp_socket: Option<UdpSocket>,
        prepared: nettool_node::PreparedRemoteSpeedSession,
        operation_id: &str,
    ) -> Result<serde_json::Value, NetToolError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let start_at = now_unix_nanoseconds()
            .checked_add(200_000_000)
            .ok_or_else(|| {
                NetToolError::new(ErrorCode::SpeedFailed, "scheduled start overflow", false)
            })?;
        if let Err(error) = prepared
            .start(client, &format!("{operation_id}-start"), start_at)
            .await
        {
            let _ = prepared.stop(client, &format!("{operation_id}-stop")).await;
            return Err(error);
        }
        let now = now_unix_nanoseconds();
        if start_at > now {
            sleep(Duration::from_nanos(start_at - now)).await;
        }
        let local = match request.protocol {
            nettool_domain::SpeedProtocol::Tcp => {
                let listener = tcp_listener.ok_or_else(|| {
                    NetToolError::new(
                        ErrorCode::SpeedFailed,
                        "TCP bidirectional receiver endpoint is unavailable",
                        false,
                    )
                })?;
                let destination = SocketAddr::new(endpoint.address.ip(), prepared.remote_data_port);
                let config = TcpRunConfig {
                    streams: request.streams.unwrap_or(1),
                    payload_bytes: usize::from(request.frame_size.unwrap_or(16_384)).max(1024),
                    warmup_milliseconds: request.warmup_ms,
                    measurement_milliseconds: request.duration_ms,
                };
                let receiver_config = nettool_speed::AuthorizedTcpReceiverConfig {
                    expected_streams: config.streams,
                    session_id: prepared.session_id,
                    authorization_tag: prepared.authorization_tag.clone(),
                };
                let sender_config = AuthorizedTcpSenderConfig {
                    run: config,
                    session_id: prepared.session_id,
                    authorization_tag: prepared.authorization_tag.clone(),
                };
                let (receiver, sender) = tokio::join!(
                    run_authorized_tcp_receiver(listener, receiver_config),
                    run_authorized_tcp_sender(destination, sender_config),
                );
                let receiver = receiver?;
                let sender = sender?;
                json!({"protocol":"tcp","sender":sender,"receiver":receiver})
            }
            nettool_domain::SpeedProtocol::Udp => {
                let socket = udp_socket.ok_or_else(|| {
                    NetToolError::new(
                        ErrorCode::SpeedFailed,
                        "UDP bidirectional receiver endpoint is unavailable",
                        false,
                    )
                })?;
                let destination = SocketAddr::new(endpoint.address.ip(), prepared.remote_data_port);
                let receiver_config = nettool_speed::UdpReceiverConfig {
                    session_id: prepared.session_id,
                    stream_id: 0,
                    expected_source: SocketAddr::new(
                        endpoint.address.ip(),
                        prepared.remote_source_data_port,
                    ),
                    maximum_datagram_bytes: usize::from(
                        request.frame_size.unwrap_or(DEFAULT_UDP_DATAGRAM_BYTES_U16),
                    )
                    .max(64),
                    idle_timeout_milliseconds: request.duration_ms.saturating_add(2_000),
                    authorization_tag: prepared.authorization_tag.clone(),
                };
                let sender_config = UdpSenderConfig {
                    session_id: prepared.session_id,
                    stream_id: 0,
                    datagram_bytes: usize::from(
                        request.frame_size.unwrap_or(DEFAULT_UDP_DATAGRAM_BYTES_U16),
                    )
                    .max(64),
                    measurement_milliseconds: request.duration_ms,
                    target_bits_per_second: request.target_rate_bps,
                    maximum_packets_per_burst: 32,
                    authorization_tag: prepared.authorization_tag.clone(),
                };
                let (receiver, sender) = tokio::join!(
                    run_udp_receiver(&socket, receiver_config),
                    run_udp_sender(&socket, destination, sender_config),
                );
                let receiver = receiver?;
                let sender = sender?;
                json!({"protocol":"udp","sender":sender,"receiver":receiver})
            }
            nettool_domain::SpeedProtocol::Raw => {
                return Err(NetToolError::new(
                    ErrorCode::ActionUnsupported,
                    "raw bidirectional executor is not attached",
                    false,
                ));
            }
        };
        let remote_result = match wait_for_remote_result(client, &prepared).await {
            Ok(result) => result,
            Err(error) => {
                let _ = prepared.stop(client, &format!("{operation_id}-stop")).await;
                return Err(error);
            }
        };
        let remote = serde_json::from_slice::<serde_json::Value>(&remote_result.result_json)
            .map_err(|error| {
                NetToolError::new(
                    ErrorCode::ProtocolInvalid,
                    format!("remote bidirectional result JSON is invalid: {error}"),
                    false,
                )
            })?;
        Ok(json!({
            "session_id": hex_node_id(prepared.session_id),
            "direction":"bidirectional",
            "local": local,
            "remote": remote,
        }))
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_prepared_download<S>(
        client: &mut nettool_node::NodeControlClient<S>,
        request: &SpeedRunRequest,
        endpoint: &TrustedNodeEndpoint,
        tcp_listener: Option<TcpListener>,
        udp_socket: Option<UdpSocket>,
        prepared: nettool_node::PreparedRemoteSpeedSession,
        operation_id: &str,
    ) -> Result<serde_json::Value, NetToolError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        if request.protocol == nettool_domain::SpeedProtocol::Tcp && tcp_listener.is_none() {
            return Err(NetToolError::new(
                ErrorCode::SpeedFailed,
                "TCP download receiver endpoint is unavailable",
                false,
            ));
        }
        if request.protocol == nettool_domain::SpeedProtocol::Udp && udp_socket.is_none() {
            return Err(NetToolError::new(
                ErrorCode::SpeedFailed,
                "UDP download receiver endpoint is unavailable",
                false,
            ));
        }
        let start_at = now_unix_nanoseconds()
            .checked_add(200_000_000)
            .ok_or_else(|| {
                NetToolError::new(ErrorCode::SpeedFailed, "scheduled start overflow", false)
            })?;
        if let Err(error) = prepared
            .start(client, &format!("{operation_id}-start"), start_at)
            .await
        {
            let _ = prepared.stop(client, &format!("{operation_id}-stop")).await;
            return Err(error);
        }
        let now = now_unix_nanoseconds();
        if start_at > now {
            sleep(Duration::from_nanos(start_at - now)).await;
        }
        let receiver = match request.protocol {
            nettool_domain::SpeedProtocol::Tcp => run_authorized_tcp_receiver(
                tcp_listener.expect("TCP listener validated above"),
                nettool_speed::AuthorizedTcpReceiverConfig {
                    expected_streams: request.streams.unwrap_or(1),
                    session_id: prepared.session_id,
                    authorization_tag: prepared.authorization_tag.clone(),
                },
            )
            .await
            .and_then(|result| {
                serde_json::to_value(result).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::ProtocolInvalid,
                        format!("cannot serialize TCP download receiver result: {error}"),
                        false,
                    )
                })
            }),
            nettool_domain::SpeedProtocol::Udp => {
                let socket = udp_socket.expect("UDP socket validated above");
                run_udp_receiver(
                    &socket,
                    nettool_speed::UdpReceiverConfig {
                        session_id: prepared.session_id,
                        stream_id: 0,
                        expected_source: SocketAddr::new(
                            endpoint.address.ip(),
                            prepared.remote_source_data_port,
                        ),
                        maximum_datagram_bytes: usize::from(
                            request.frame_size.unwrap_or(DEFAULT_UDP_DATAGRAM_BYTES_U16),
                        )
                        .max(64),
                        idle_timeout_milliseconds: request.duration_ms.saturating_add(2_000),
                        authorization_tag: prepared.authorization_tag.clone(),
                    },
                )
                .await
                .and_then(|result| {
                    serde_json::to_value(result).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::ProtocolInvalid,
                            format!("cannot serialize UDP download receiver result: {error}"),
                            false,
                        )
                    })
                })
            }
            nettool_domain::SpeedProtocol::Raw => Err(NetToolError::new(
                ErrorCode::ActionUnsupported,
                "raw data-plane executor is not attached",
                false,
            )),
        };
        let receiver = match receiver {
            Ok(result) => result,
            Err(error) => {
                let _ = prepared.stop(client, &format!("{operation_id}-stop")).await;
                return Err(error);
            }
        };
        let remote_result = match wait_for_remote_result(client, &prepared).await {
            Ok(result) => result,
            Err(error) => {
                let _ = prepared.stop(client, &format!("{operation_id}-stop")).await;
                return Err(error);
            }
        };
        let sender = serde_json::from_slice::<serde_json::Value>(&remote_result.result_json)
            .map_err(|error| {
                NetToolError::new(
                    ErrorCode::ProtocolInvalid,
                    format!("remote sender result JSON is invalid: {error}"),
                    false,
                )
            })?;
        Ok(json!({
            "session_id": hex_node_id(prepared.session_id),
            "sender": sender,
            "receiver": receiver,
        }))
    }

    async fn run_upload_sender(
        request: &SpeedRunRequest,
        destination: SocketAddr,
        udp_socket: Option<&tokio::net::UdpSocket>,
        prepared: &nettool_node::PreparedRemoteSpeedSession,
    ) -> Result<serde_json::Value, NetToolError> {
        match request.protocol {
            nettool_domain::SpeedProtocol::Tcp => {
                let config = TcpRunConfig {
                    streams: request.streams.unwrap_or(1),
                    payload_bytes: usize::from(request.frame_size.unwrap_or(16_384)).max(1024),
                    warmup_milliseconds: request.warmup_ms,
                    measurement_milliseconds: request.duration_ms,
                };
                serde_json::to_value(
                    run_authorized_tcp_sender(
                        destination,
                        AuthorizedTcpSenderConfig {
                            run: config,
                            session_id: prepared.session_id,
                            authorization_tag: prepared.authorization_tag.clone(),
                        },
                    )
                    .await?,
                )
                .map_err(|error| {
                    NetToolError::new(
                        ErrorCode::ProtocolInvalid,
                        format!("cannot serialize TCP result: {error}"),
                        false,
                    )
                })
            }
            nettool_domain::SpeedProtocol::Udp => {
                let socket = udp_socket.ok_or_else(|| {
                    NetToolError::new(
                        ErrorCode::SpeedFailed,
                        "UDP source socket is unavailable",
                        false,
                    )
                })?;
                serde_json::to_value(
                    run_udp_sender(
                        socket,
                        destination,
                        UdpSenderConfig {
                            session_id: prepared.session_id,
                            stream_id: 0,
                            datagram_bytes: usize::from(request.frame_size.unwrap_or(1_200))
                                .max(64),
                            measurement_milliseconds: request.duration_ms,
                            target_bits_per_second: request.target_rate_bps,
                            maximum_packets_per_burst: 32,
                            authorization_tag: prepared.authorization_tag.clone(),
                        },
                    )
                    .await?,
                )
                .map_err(|error| {
                    NetToolError::new(
                        ErrorCode::ProtocolInvalid,
                        format!("cannot serialize UDP result: {error}"),
                        false,
                    )
                })
            }
            nettool_domain::SpeedProtocol::Raw => Err(NetToolError::new(
                ErrorCode::ActionUnsupported,
                "raw data-plane executor is not attached",
                false,
            )),
        }
    }

    async fn wait_for_remote_result<S>(
        client: &mut nettool_node::NodeControlClient<S>,
        session: &nettool_node::PreparedRemoteSpeedSession,
    ) -> Result<nettool_node_protocol::TestResult, NetToolError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            match session.result(client).await {
                Ok(result) => return Ok(result),
                Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                    sleep(Duration::from_millis(25)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn trusted_connection_config(
        node: TrustedNodeSummary,
        runtime: &AgentRuntime,
    ) -> Result<(TrustedNodeEndpoint, Arc<rustls::ClientConfig>), NetToolError> {
        let address = node.control_address.parse().map_err(|_| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                "trusted Node control address is invalid",
                false,
            )
        })?;
        let node_id = parse_node_id(&node.id)?;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(node.certificate_der))
            .map_err(|error| {
                NetToolError::new(
                    ErrorCode::NodeTlsFailed,
                    format!("trusted Node certificate cannot be used as a root: {error}"),
                    false,
                )
            })?;
        let tls = tls13_client_config(
            roots,
            runtime.identity_material.certificate_chain.clone(),
            runtime.identity_material.private_key.clone_key(),
        )?;
        let endpoint = TrustedNodeEndpoint {
            address,
            server_name: node.server_name,
            node_id,
            public_key_fingerprint: node.fingerprint,
            timeout_milliseconds: 10_000,
        };
        Ok((endpoint, Arc::new(tls)))
    }

    fn parse_node_id(value: &str) -> Result<[u8; 16], NetToolError> {
        if value.len() != 32 {
            return Err(NetToolError::new(
                ErrorCode::ProtocolInvalid,
                "trusted Node ID is not 128-bit hexadecimal",
                false,
            ));
        }
        let mut node_id = [0_u8; 16];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(chunk).map_err(|_| {
                NetToolError::new(
                    ErrorCode::ProtocolInvalid,
                    "trusted Node ID contains invalid text",
                    false,
                )
            })?;
            node_id[index] = u8::from_str_radix(text, 16).map_err(|_| {
                NetToolError::new(
                    ErrorCode::ProtocolInvalid,
                    "trusted Node ID is not hexadecimal",
                    false,
                )
            })?;
        }
        if node_id == [0; 16] {
            return Err(NetToolError::new(
                ErrorCode::ProtocolInvalid,
                "trusted Node ID must not be zero",
                false,
            ));
        }
        Ok(node_id)
    }

    #[allow(clippy::too_many_lines)]
    fn execute(action: &str, payload: &[u8], storage: &Storage) -> ActionResponse {
        if ActionRegistry::find(action).is_none() {
            return failure("ACTION.UNKNOWN", "action is not registered", false);
        }
        let result = match action {
            "system.health" => storage.schema_version().map(|version| json!({"status":"healthy","schema_version":version})),
            "interface.list" | "interface.refresh" => probe_environment().map(|report| {
                json!({
                    "schema_version": report.schema_version,
                    "interfaces": report.nics.iter().map(|nic| json!({
                        "name": nic.name,
                        "pci_address": nic.pci_address,
                        "driver": nic.driver,
                        "link_speed_mbps": nic.link_speed_mbps,
                        "rx_queues": nic.rx_queues,
                        "tx_queues": nic.tx_queues,
                        "numa_node": nic.numa_node
                    })).collect::<Vec<_>>()
                })
            }),
            "interface.show" => parse_interface_target(payload).and_then(|request| {
                probe_environment().and_then(|report| {
                    let nic = report.nics.iter().find(|nic| {
                        nic.name == request.name_or_id
                            || nic.pci_address.as_deref() == Some(request.name_or_id.as_str())
                    });
                    nic.map_or_else(
                        || {
                            Err(NetToolError::new(
                                ErrorCode::InvalidArgument,
                                "interface does not exist",
                                false,
                            ))
                        },
                        |nic| {
                            Ok(json!({
                                "schema_version": report.schema_version,
                                "interface": {
                                    "name": nic.name,
                                    "pci_address": nic.pci_address,
                                    "driver": nic.driver,
                                    "link_speed_mbps": nic.link_speed_mbps,
                                    "rx_queues": nic.rx_queues,
                                    "tx_queues": nic.tx_queues,
                                    "numa_node": nic.numa_node
                                }
                            }))
                        },
                    )
                })
            }),
            "profile.list" => storage.list_profiles().and_then(|profiles| serde_json::to_value(profiles).map_err(|error| storage_error(error.to_string()))),
            "profile.show" => parse_profile_target(payload).and_then(|request| {
                storage
                    .get_profile(&request.id_or_name)?
                    .map_or_else(
                        || Err(NetToolError::new(ErrorCode::InvalidArgument, "profile does not exist", false)),
                        |value| serde_json::to_value(value).map_err(|error| storage_error(error.to_string())),
                    )
            }),
            "profile.export" => parse_profile_target(payload).and_then(|request| {
                storage
                    .get_profile(&request.id_or_name)?
                    .map_or_else(
                        || Err(NetToolError::new(ErrorCode::InvalidArgument, "profile does not exist", false)),
                        |document| Ok(json!({
                            "format": "nettool.profile.v1",
                            "id": document.summary.id,
                            "name": document.summary.name,
                            "revision": document.summary.active_revision,
                            "configuration": document.configuration,
                        })),
                    )
            }),
            "node.list" | "node.status" => storage.list_trusted_nodes().map(|nodes| json!({
                    "schema_version": "1.0",
                    "nodes": nodes.into_iter().map(|node| json!({
                        "id": node.id,
                        "name": node.name,
                        "last_address": node.last_address,
                        "fingerprint": node.fingerprint,
                        "server_name": node.server_name,
                        "control_address": node.control_address,
                        "state": "trusted",
                    })).collect::<Vec<_>>()
                })),
            "dataplane.probe" => probe_environment().map(|report| json!({"schema_version":report.schema_version,"platform":report.platform.as_str(),"logical_cpus":report.logical_cpus,"numa_nodes":report.numa_nodes,"huge_pages_total":report.huge_pages_total,"huge_pages_free":report.huge_pages_free,"huge_page_size_kib":report.huge_page_size_kib,"nics":report.nics.iter().map(|nic| json!({"name":nic.name,"pci_address":nic.pci_address,"driver":nic.driver,"link_speed_mbps":nic.link_speed_mbps,"rx_queues":nic.rx_queues,"tx_queues":nic.tx_queues,"numa_node":nic.numa_node})).collect::<Vec<_>>(),"dpdk_capable":report.dpdk_capable,"af_xdp_capable":report.af_xdp_capable,"af_xdp_zero_copy_capable":report.af_xdp_zero_copy_capable,"rio_platform_capable":cfg!(target_os = "windows"),"rio_implementation_available":nettool_backend_rio::is_backend_built(),"warnings":report.warnings})),
            "perf.topology" => probe_environment().map(|report| json!({
                "schema_version":"1.0",
                "platform":report.platform.as_str(),
                "cpu":{"logical_count":report.logical_cpus},
                "numa":{"node_count":report.numa_nodes},
                "huge_pages":{"total":report.huge_pages_total,"free":report.huge_pages_free,"size_kib":report.huge_page_size_kib},
                "nics":report.nics.iter().map(|nic| json!({
                    "name":nic.name,
                    "pci_address":nic.pci_address,
                    "link_speed_mbps":nic.link_speed_mbps,
                    "numa_node":nic.numa_node,
                    "rx_queues":nic.rx_queues,
                    "tx_queues":nic.tx_queues,
                    "driver":nic.driver
                })).collect::<Vec<_>>(),
                "warnings":report.warnings
            })),
            "perf.backend" => probe_environment().map(|report| {
                let dpdk_built = nettool_backend_dpdk::is_backend_built();
                let rio_built = nettool_backend_rio::is_backend_built();
                let rio_preflight = nettool_backend_rio::evaluate_rio_preflight(
                    cfg!(target_os = "windows"),
                    rio_built,
                );
                json!({
                    "schema_version":"1.0",
                    "backends":[
                        {"id":"pcap","available":true,"mode":"offline","implementation_available":true},
                        {"id":"af_xdp","available":report.af_xdp_capable && nettool_backend_af_xdp::is_backend_built(),"mode":"accelerated","platform_capable":report.af_xdp_capable,"implementation_available":nettool_backend_af_xdp::is_backend_built()},
                        {"id":"dpdk","available":dpdk_built && report.dpdk_capable,"mode":"accelerated","runtime_available":report.dpdk_capable,"implementation_available":dpdk_built},
                        {"id":"rio","available":rio_preflight.can_run,"mode":"accelerated","platform_capable":cfg!(target_os = "windows"),"implementation_available":rio_built,"preflight_can_run":rio_preflight.can_run,"preflight_checks":rio_preflight.checks.iter().map(|check| json!({"id":check.id,"severity":format!("{:?}",check.severity),"message":check.message})).collect::<Vec<_>>()}
                    ],
                    "warnings":report.warnings
                })
            }),
            "perf.profile.list" => Ok(json!({
                "schema_version":"1.0",
                "profiles":BenchmarkProfileRegistry::ids().into_iter().filter_map(|id| {
                    BenchmarkProfileRegistry::get(id).map(|profile| json!({
                        "id":id,
                        "plan":profile.plan,
                        "certification_policy_configured":profile.certification_policy.is_some()
                    }))
                }).collect::<Vec<_>>()
            })),
            "speed.run" => parse_speed_payload(payload).and_then(|request| {
                request.validate()?;
                let node = storage.resolve_trusted_node(&request.node)?.ok_or_else(|| {
                    NetToolError::new(
                        ErrorCode::NodeNotPaired,
                        "speed target is not a trusted paired node",
                        false,
                    )
                })?;
                validate_accelerated_backend(&request)?;
                Err(NetToolError::new(
                    ErrorCode::ActionUnsupported,
                    format!(
                        "speed request for trusted node {} is valid, but Agent control transport orchestration is not attached",
                        node.id
                    ),
                    false,
                ))
            }),
            "speed.history" => {
                serde_json::from_slice::<SpeedHistoryPayload>(payload)
                    .map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid speed history payload: {error}"),
                            false,
                        )
                    })
                    .and_then(|request| {
                        if request
                            .format
                            .as_deref()
                            .is_some_and(|format| format != "json" && format != "csv")
                        {
                            return Err(NetToolError::new(
                                ErrorCode::InvalidArgument,
                                "speed history format must be json or csv",
                                false,
                            ));
                        }
                        storage
                            .list_speed_sessions(request.limit.unwrap_or(100))
                            .and_then(|sessions| {
                                serde_json::to_value(sessions)
                                    .map_err(|error| storage_error(error.to_string()))
                            })
                    })
            }
            "perf.benchmark" => parse_benchmark_payload(payload).and_then(|request| {
                let profile = BenchmarkProfileRegistry::get(&request.profile).ok_or_else(|| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "benchmark profile does not exist",
                        false,
                    )
                })?;
                profile.plan.validate()?;
                Err(NetToolError::new(
                    ErrorCode::BackendNotBuilt,
                    "benchmark plan is valid, but no accelerated hardware phase executor is linked",
                    false,
                ))
            }),
            _ => return failure("ACTION.NOT_IMPLEMENTED", "registered action is not implemented in this milestone", false),
        };
        match result {
            Ok(value) => ActionResponse {
                success: true,
                data_json: serde_json::to_vec(&value).unwrap_or_default(),
                error_code: String::new(),
                error_message: String::new(),
                retryable: false,
            },
            Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
        }
    }

    fn storage_error(message: String) -> NetToolError {
        NetToolError::new(ErrorCode::StorageFailed, message, false)
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BenchmarkPayload {
        profile: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CancelPayload {
        session_id: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SpeedHistoryPayload {
        limit: Option<u32>,
        #[serde(default)]
        format: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProfileCreatePayload {
        id: String,
        name: String,
        configuration: serde_json::Value,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProfileEditPayload {
        id_or_name: String,
        name: String,
        configuration: serde_json::Value,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProfileImportPayload {
        id: String,
        name: String,
        configuration: serde_json::Value,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProfileTargetPayload {
        id_or_name: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct InterfaceTargetPayload {
        name_or_id: String,
    }

    fn parse_interface_target(payload: &[u8]) -> Result<InterfaceTargetPayload, NetToolError> {
        serde_json::from_slice(payload).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("invalid interface target payload: {error}"),
                false,
            )
        })
    }

    fn parse_profile_target(payload: &[u8]) -> Result<ProfileTargetPayload, NetToolError> {
        serde_json::from_slice(payload).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("invalid profile target payload: {error}"),
                false,
            )
        })
    }

    fn execute_profile_mutation(
        action: &str,
        payload: &[u8],
        storage: &mut Storage,
    ) -> Result<serde_json::Value, NetToolError> {
        match action {
            "node.revoke" => {
                let request = parse_profile_target(payload)?;
                let node = storage.revoke_trusted_node(&request.id_or_name)?;
                Ok(json!({
                    "revoked": true,
                    "node_id": node.id,
                    "name": node.name,
                    "fingerprint": node.fingerprint,
                }))
            }
            "node.pair" => {
                let request: NodePairPayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid node pair payload: {error}"),
                            false,
                        )
                    })?;
                storage.trust_node_connection(&TrustedNodeConnection {
                    node_id: &request.node_id,
                    name: &request.name,
                    control_address: &request.control_address,
                    server_name: &request.server_name,
                    certificate_der: &request.certificate_der,
                    fingerprint: &request.fingerprint,
                    out_of_band_fingerprint_confirmed: request.out_of_band_fingerprint_confirmed,
                    identity_change_confirmed: request.identity_change_confirmed,
                })?;
                Ok(json!({
                    "paired": true,
                    "node_id": request.node_id,
                    "name": request.name,
                    "control_address": request.control_address,
                    "fingerprint": request.fingerprint,
                }))
            }
            "profile.create" => {
                let request: ProfileCreatePayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid profile create payload: {error}"),
                            false,
                        )
                    })?;
                let summary = storage.create_profile(
                    &request.id,
                    &request.name,
                    &request.configuration,
                    &utc_timestamp(),
                )?;
                serde_json::to_value(summary).map_err(|error| storage_error(error.to_string()))
            }
            "profile.edit" => {
                let request: ProfileEditPayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid profile edit payload: {error}"),
                            false,
                        )
                    })?;
                let summary = storage.update_profile(
                    &request.id_or_name,
                    &request.name,
                    &request.configuration,
                    &utc_timestamp(),
                )?;
                serde_json::to_value(summary).map_err(|error| storage_error(error.to_string()))
            }
            "profile.import" => {
                let request: ProfileImportPayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid profile import payload: {error}"),
                            false,
                        )
                    })?;
                let summary = storage.create_profile(
                    &request.id,
                    &request.name,
                    &request.configuration,
                    &utc_timestamp(),
                )?;
                serde_json::to_value(summary).map_err(|error| storage_error(error.to_string()))
            }
            "profile.delete" => {
                let request = parse_profile_target(payload)?;
                let summary = storage.delete_profile(&request.id_or_name)?;
                serde_json::to_value(summary).map_err(|error| storage_error(error.to_string()))
            }
            _ => Err(NetToolError::new(
                ErrorCode::ActionUnsupported,
                "profile action is not mutable",
                false,
            )),
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NodePairPayload {
        node_id: String,
        name: String,
        control_address: String,
        server_name: String,
        fingerprint: String,
        certificate_der: Vec<u8>,
        out_of_band_fingerprint_confirmed: bool,
        identity_change_confirmed: bool,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProfileApplyPayload {
        id_or_name: String,
        interface_id: String,
        #[serde(default)]
        confirm_timeout_seconds: Option<u64>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct IpSetPayload {
        interface_id: String,
        address: String,
        prefix_length: u8,
        gateway: Option<String>,
        #[serde(default)]
        confirm_timeout_seconds: Option<u64>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct IpDhcpPayload {
        interface_id: String,
        #[serde(default)]
        confirm_timeout_seconds: Option<u64>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DnsSetPayload {
        interface_id: String,
        servers: Vec<String>,
        #[serde(default)]
        confirm_timeout_seconds: Option<u64>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HelperOperationPayload {
        operation_id: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HostsReplacePayload {
        profile_id: String,
        entries: Vec<ManagedHostsEntry>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HostsAddPayload {
        profile_id: String,
        address: String,
        hostname: String,
        #[serde(default)]
        comment: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HostsRemovePayload {
        profile_id: String,
        hostname: String,
    }

    type HostsTogglePayload = HostsRemovePayload;

    #[allow(clippy::too_many_lines)]
    async fn execute_helper_action(
        action: &str,
        payload: &[u8],
        operation_id: &str,
        dry_run: bool,
        runtime: &AgentRuntime,
    ) -> Result<serde_json::Value, NetToolError> {
        if matches!(
            action,
            "hosts.add" | "hosts.remove" | "hosts.enable" | "hosts.disable"
        ) {
            return execute_hosts_mutation(action, payload, operation_id, dry_run).await;
        }
        let (operation, helper_operation_id) = match action {
            "profile.apply" => {
                let request: ProfileApplyPayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid profile apply payload: {error}"),
                            false,
                        )
                    })?;
                let document = runtime
                    .storage
                    .lock()
                    .await
                    .get_profile(&request.id_or_name)?
                    .ok_or_else(|| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            "profile does not exist",
                            false,
                        )
                    })?;
                let desired_state = network_desired_state_from_profile(document.configuration)?;
                let helper_operation_id = if operation_id.trim().is_empty() {
                    format!(
                        "profile-apply-{}-{}",
                        document.summary.id, request.interface_id
                    )
                } else {
                    operation_id.to_owned()
                };
                (
                    PrivilegedOperation::NetworkApply {
                        interface_id: request.interface_id,
                        desired_state,
                        confirm_timeout_seconds: request.confirm_timeout_seconds.unwrap_or(60),
                    },
                    helper_operation_id,
                )
            }
            "profile.confirm" => {
                let request: HelperOperationPayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid profile confirm payload: {error}"),
                            false,
                        )
                    })?;
                (
                    PrivilegedOperation::SafeApplyConfirm {
                        operation_id: request.operation_id.clone(),
                    },
                    request.operation_id,
                )
            }
            "profile.rollback" => {
                let request: HelperOperationPayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid profile rollback payload: {error}"),
                            false,
                        )
                    })?;
                (
                    PrivilegedOperation::SafeApplyRollback {
                        operation_id: request.operation_id.clone(),
                    },
                    request.operation_id,
                )
            }
            "ip.set" => {
                let request: IpSetPayload = serde_json::from_slice(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid ip set payload: {error}"),
                        false,
                    )
                })?;
                let address = request.address.parse::<std::net::IpAddr>().map_err(|_| {
                    NetToolError::new(ErrorCode::InvalidArgument, "IP address is invalid", false)
                })?;
                let gateway = request
                    .gateway
                    .as_deref()
                    .map(str::parse::<std::net::IpAddr>)
                    .transpose()
                    .map_err(|_| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            "gateway address is invalid",
                            false,
                        )
                    })?;
                if gateway.is_some_and(|value| value.is_ipv4() != address.is_ipv4()) {
                    return Err(NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "gateway address family does not match IP address",
                        false,
                    ));
                }
                let (ipv4, ipv6, destination) = if address.is_ipv4() {
                    (
                        nettool_domain::Ipv4Configuration::Static {
                            addresses: vec![nettool_domain::IpPrefix {
                                address,
                                prefix_length: request.prefix_length,
                            }],
                        },
                        nettool_domain::Ipv6Configuration::Automatic,
                        nettool_domain::IpPrefix {
                            address: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            prefix_length: 0,
                        },
                    )
                } else {
                    (
                        nettool_domain::Ipv4Configuration::Dhcp,
                        nettool_domain::Ipv6Configuration::Static {
                            addresses: vec![nettool_domain::IpPrefix {
                                address,
                                prefix_length: request.prefix_length,
                            }],
                        },
                        nettool_domain::IpPrefix {
                            address: std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                            prefix_length: 0,
                        },
                    )
                };
                (
                    PrivilegedOperation::NetworkApply {
                        interface_id: request.interface_id,
                        desired_state: NetworkDesiredState {
                            ipv4,
                            ipv6,
                            dns: nettool_domain::DnsConfiguration {
                                automatic: true,
                                servers: Vec::new(),
                                search_domains: Vec::new(),
                            },
                            routes: request
                                .gateway
                                .map(|_| nettool_domain::RouteConfiguration {
                                    destination,
                                    gateway,
                                    metric: None,
                                })
                                .into_iter()
                                .collect(),
                            mtu: None,
                        },
                        confirm_timeout_seconds: request.confirm_timeout_seconds.unwrap_or(60),
                    },
                    operation_id.to_owned(),
                )
            }
            "ip.dhcp" => {
                let request: IpDhcpPayload = serde_json::from_slice(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid ip dhcp payload: {error}"),
                        false,
                    )
                })?;
                (
                    PrivilegedOperation::NetworkApply {
                        interface_id: request.interface_id,
                        desired_state: NetworkDesiredState {
                            ipv4: nettool_domain::Ipv4Configuration::Dhcp,
                            ipv6: nettool_domain::Ipv6Configuration::Automatic,
                            dns: nettool_domain::DnsConfiguration {
                                automatic: true,
                                servers: Vec::new(),
                                search_domains: Vec::new(),
                            },
                            routes: Vec::new(),
                            mtu: None,
                        },
                        confirm_timeout_seconds: request.confirm_timeout_seconds.unwrap_or(60),
                    },
                    operation_id.to_owned(),
                )
            }
            "dns.set" => {
                let request: DnsSetPayload = serde_json::from_slice(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid dns set payload: {error}"),
                        false,
                    )
                })?;
                let servers = request
                    .servers
                    .iter()
                    .map(|value| value.parse::<std::net::IpAddr>())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            "DNS server address is invalid",
                            false,
                        )
                    })?;
                (
                    PrivilegedOperation::NetworkApply {
                        interface_id: request.interface_id,
                        desired_state: NetworkDesiredState {
                            ipv4: nettool_domain::Ipv4Configuration::Dhcp,
                            ipv6: nettool_domain::Ipv6Configuration::Automatic,
                            dns: nettool_domain::DnsConfiguration {
                                automatic: false,
                                servers,
                                search_domains: Vec::new(),
                            },
                            routes: Vec::new(),
                            mtu: None,
                        },
                        confirm_timeout_seconds: request.confirm_timeout_seconds.unwrap_or(60),
                    },
                    operation_id.to_owned(),
                )
            }
            "hosts.replace" => {
                let request: HostsReplacePayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid hosts replace payload: {error}"),
                            false,
                        )
                    })?;
                let helper_operation_id = if operation_id.trim().is_empty() {
                    let entries_json = serde_json::to_vec(&request.entries).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::ProtocolInvalid,
                            format!("hosts entries cannot be fingerprinted: {error}"),
                            false,
                        )
                    })?;
                    let mut entries_digest = String::with_capacity(64);
                    for byte in Sha256::digest(entries_json) {
                        let _ = write!(entries_digest, "{byte:02x}");
                    }
                    format!("hosts-replace-{}-{}", request.profile_id, entries_digest)
                } else {
                    operation_id.to_owned()
                };
                (
                    PrivilegedOperation::HostsAtomicReplace {
                        profile_id: request.profile_id,
                        entries: request.entries,
                    },
                    helper_operation_id,
                )
            }
            "hosts.read" => (
                PrivilegedOperation::HostsRead,
                if operation_id.trim().is_empty() {
                    "hosts-read".to_owned()
                } else {
                    operation_id.to_owned()
                },
            ),
            "hosts.backup" => (
                PrivilegedOperation::HostsBackup,
                if operation_id.trim().is_empty() {
                    "hosts-backup".to_owned()
                } else {
                    operation_id.to_owned()
                },
            ),
            "hosts.restore" => (
                PrivilegedOperation::HostsRestore,
                if operation_id.trim().is_empty() {
                    "hosts-restore".to_owned()
                } else {
                    operation_id.to_owned()
                },
            ),
            _ => {
                return Err(NetToolError::new(
                    ErrorCode::ActionUnsupported,
                    "helper action is not attached",
                    false,
                ));
            }
        };
        helper_call(&helper_operation_id, operation, dry_run).await
    }

    async fn execute_hosts_mutation(
        action: &str,
        payload: &[u8],
        operation_id: &str,
        dry_run: bool,
    ) -> Result<serde_json::Value, NetToolError> {
        let (profile_id, hostname, replacement) = match action {
            "hosts.add" => {
                let request: HostsAddPayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid hosts add payload: {error}"),
                            false,
                        )
                    })?;
                let current = read_managed_hosts(&request.profile_id, operation_id).await?;
                if current
                    .iter()
                    .any(|entry| entry.hostname == request.hostname)
                {
                    return Err(NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "hosts hostname already exists in profile",
                        false,
                    ));
                }
                let mut entries = current;
                entries.push(ManagedHostsEntry {
                    address: request.address,
                    hostname: request.hostname.clone(),
                    comment: request.comment,
                    enabled: true,
                });
                (request.profile_id, request.hostname, entries)
            }
            "hosts.remove" => {
                let request: HostsRemovePayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid hosts remove payload: {error}"),
                            false,
                        )
                    })?;
                let mut entries = read_managed_hosts(&request.profile_id, operation_id).await?;
                let before = entries.len();
                entries.retain(|entry| entry.hostname != request.hostname);
                if entries.len() == before {
                    return Ok(
                        json!({"updated": false, "entry_count": before, "hostname": request.hostname}),
                    );
                }
                (request.profile_id, request.hostname, entries)
            }
            "hosts.enable" | "hosts.disable" => {
                let request: HostsTogglePayload =
                    serde_json::from_slice(payload).map_err(|error| {
                        NetToolError::new(
                            ErrorCode::InvalidArgument,
                            format!("invalid hosts toggle payload: {error}"),
                            false,
                        )
                    })?;
                let mut entries = read_managed_hosts(&request.profile_id, operation_id).await?;
                let enabled = action == "hosts.enable";
                let mut found = false;
                for entry in &mut entries {
                    if entry.hostname == request.hostname {
                        entry.enabled = enabled;
                        found = true;
                    }
                }
                if !found {
                    return Err(NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "hosts hostname does not exist in profile",
                        false,
                    ));
                }
                (request.profile_id, request.hostname, entries)
            }
            _ => unreachable!(),
        };
        let replace_operation_id = if operation_id.trim().is_empty() {
            format!("hosts-mutation-{profile_id}-{hostname}")
        } else {
            operation_id.to_owned()
        };
        let result = helper_call(
            &replace_operation_id,
            PrivilegedOperation::HostsAtomicReplace {
                profile_id,
                entries: replacement,
            },
            dry_run,
        )
        .await?;
        Ok(result)
    }

    async fn read_managed_hosts(
        profile_id: &str,
        operation_id: &str,
    ) -> Result<Vec<ManagedHostsEntry>, NetToolError> {
        let read_operation_id = if operation_id.trim().is_empty() {
            format!("hosts-read-{profile_id}")
        } else {
            format!("{operation_id}-read")
        };
        let value = helper_call(&read_operation_id, PrivilegedOperation::HostsRead, false).await?;
        let content = value.as_str().ok_or_else(|| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                "helper hosts response is not text",
                false,
            )
        })?;
        parse_managed_hosts(content, profile_id)
    }

    fn parse_managed_hosts(
        content: &str,
        profile_id: &str,
    ) -> Result<Vec<ManagedHostsEntry>, NetToolError> {
        let begin = format!("# BEGIN NETTOOL PROFILE {profile_id}");
        let end = format!("# END NETTOOL PROFILE {profile_id}");
        let lines = content.lines().collect::<Vec<_>>();
        let starts = lines.iter().filter(|line| line.trim() == begin).count();
        let ends = lines.iter().filter(|line| line.trim() == end).count();
        if starts == 0 && ends == 0 {
            return Ok(Vec::new());
        }
        if starts != 1 || ends != 1 {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "managed hosts markers are missing or duplicated",
                false,
            ));
        }
        let start = lines
            .iter()
            .position(|line| line.trim() == begin)
            .unwrap_or(0);
        let finish = lines
            .iter()
            .position(|line| line.trim() == end)
            .unwrap_or(0);
        if finish <= start {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "managed hosts markers are out of order",
                false,
            ));
        }
        let mut entries = Vec::new();
        for line in &lines[start + 1..finish] {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (line, enabled) = line
                .strip_prefix("# NETTOOL DISABLED ")
                .map_or((line, true), |value| (value.trim_start(), false));
            let (fields, comment) = line.split_once('#').map_or((line, None), |(value, note)| {
                (value.trim_end(), Some(note.trim().to_owned()))
            });
            let mut fields = fields.split_whitespace();
            let address = fields.next().ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "managed hosts entry is invalid",
                    false,
                )
            })?;
            let hostname = fields.next().ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "managed hosts entry is invalid",
                    false,
                )
            })?;
            if fields.next().is_some() {
                return Err(NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "managed hosts entry is invalid",
                    false,
                ));
            }
            address.parse::<std::net::IpAddr>().map_err(|_| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "managed hosts address is invalid",
                    false,
                )
            })?;
            entries.push(ManagedHostsEntry {
                address: address.to_owned(),
                hostname: hostname.to_owned(),
                comment,
                enabled,
            });
        }
        Ok(entries)
    }

    fn network_desired_state_from_profile(
        configuration: serde_json::Value,
    ) -> Result<NetworkDesiredState, NetToolError> {
        if let Ok(desired_state) =
            serde_json::from_value::<NetworkDesiredState>(configuration.clone())
        {
            return Ok(desired_state);
        }
        let profile: nettool_domain::NetworkProfile = serde_json::from_value(configuration)
            .map_err(|error| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("profile configuration is not a valid network profile: {error}"),
                    false,
                )
            })?;
        Ok(NetworkDesiredState {
            ipv4: profile.ipv4,
            ipv6: profile.ipv6,
            dns: profile.dns,
            routes: profile.routes,
            mtu: profile.mtu,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn helper_call(
        operation_id: &str,
        operation: PrivilegedOperation,
        dry_run: bool,
    ) -> Result<serde_json::Value, NetToolError> {
        if operation_id.trim().is_empty() {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "helper operation ID must not be empty",
                false,
            ));
        }
        operation
            .validate()
            .map_err(|message| NetToolError::new(ErrorCode::InvalidArgument, message, false))?;
        let path = std::env::var_os("NETTOOL_HELPER_SOCKET").ok_or_else(|| {
            NetToolError::new(
                ErrorCode::Unsupported,
                "privileged helper socket is not configured",
                false,
            )
        })?;
        let mut stream =
            tokio::time::timeout(Duration::from_secs(2), connect_helper(PathBuf::from(path)))
                .await
                .map_err(|_| {
                    NetToolError::new(
                        ErrorCode::HelperTransportFailed,
                        "helper connect timed out",
                        true,
                    )
                })?
                .map_err(|error| {
                    NetToolError::new(
                        ErrorCode::HelperTransportFailed,
                        format!("helper connect failed: {error}"),
                        true,
                    )
                })?;
        let request_id = format!("agent-{}", hex_node_id(random_session_id()?));
        let request = PrivilegedWireRequest {
            request_id: request_id.clone(),
            operation_id: operation_id.to_owned(),
            operation,
            dry_run,
        };
        let bytes = serde_json::to_vec(&request).map_err(|error| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                format!("helper request cannot be encoded: {error}"),
                false,
            )
        })?;
        if bytes.len() > 1_048_576 {
            return Err(NetToolError::new(
                ErrorCode::ControlFrameTooLarge,
                "helper request exceeds frame limit",
                false,
            ));
        }
        stream
            .write_u32(u32::try_from(bytes.len()).unwrap_or(u32::MAX))
            .await
            .map_err(|error| {
                NetToolError::new(
                    ErrorCode::HelperTransportFailed,
                    format!("helper request length failed: {error}"),
                    true,
                )
            })?;
        stream.write_all(&bytes).await.map_err(|error| {
            NetToolError::new(
                ErrorCode::HelperTransportFailed,
                format!("helper request failed: {error}"),
                true,
            )
        })?;
        stream.flush().await.map_err(|error| {
            NetToolError::new(
                ErrorCode::HelperTransportFailed,
                format!("helper request flush failed: {error}"),
                true,
            )
        })?;
        let length = tokio::time::timeout(Duration::from_secs(2), stream.read_u32())
            .await
            .map_err(|_| {
                NetToolError::new(
                    ErrorCode::HelperTransportFailed,
                    "helper response timed out",
                    true,
                )
            })?
            .map_err(|error| {
                NetToolError::new(
                    ErrorCode::HelperTransportFailed,
                    format!("helper response length failed: {error}"),
                    true,
                )
            })? as usize;
        if length == 0 || length > 1_048_576 {
            return Err(NetToolError::new(
                ErrorCode::ControlFrameTooLarge,
                "helper response length is invalid",
                false,
            ));
        }
        let mut response_bytes = vec![0_u8; length];
        stream
            .read_exact(&mut response_bytes)
            .await
            .map_err(|error| {
                NetToolError::new(
                    ErrorCode::HelperTransportFailed,
                    format!("helper response failed: {error}"),
                    true,
                )
            })?;
        let response: PrivilegedResponse =
            serde_json::from_slice(&response_bytes).map_err(|error| {
                NetToolError::new(
                    ErrorCode::ProtocolInvalid,
                    format!("helper response is invalid: {error}"),
                    false,
                )
            })?;
        if response.request_id != request_id {
            return Err(NetToolError::new(
                ErrorCode::ProtocolInvalid,
                "helper response request ID mismatch",
                false,
            ));
        }
        if let Some(error) = response.error {
            return Err(NetToolError::new(
                ErrorCode::HelperExecutionFailed,
                error.message,
                error.retryable,
            ));
        }
        response.result.ok_or_else(|| {
            NetToolError::new(
                ErrorCode::HelperExecutionFailed,
                "helper response has no result",
                false,
            )
        })
    }

    #[cfg(unix)]
    async fn connect_helper(path: PathBuf) -> Result<UnixStream, std::io::Error> {
        UnixStream::connect(path).await
    }

    #[cfg(windows)]
    async fn connect_helper(path: PathBuf) -> Result<NamedPipeClient, std::io::Error> {
        ClientOptions::new().open(path)
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

    fn parse_benchmark_payload(payload: &[u8]) -> Result<BenchmarkPayload, NetToolError> {
        serde_json::from_slice(payload).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("invalid benchmark payload: {error}"),
                false,
            )
        })
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
        #[cfg(target_os = "linux")]
        use super::execute_packet_stats;
        use super::{
            AgentRuntime, execute, execute_with_runtime, handle_node_connection, hex_node_id,
            parse_managed_hosts,
        };
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
            let storage = Storage::in_memory().expect("storage");
            let response = execute("perf.backend", b"{}", &storage);
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
            let storage = Storage::in_memory().expect("storage");
            let unknown = execute("perf.benchmark", br#"{"profile":"missing"}"#, &storage);
            assert_eq!(unknown.error_code, "CLI.INVALID_ARGUMENT");
            let known = execute("perf.benchmark", br#"{"profile":"100g-cert"}"#, &storage);
            assert_eq!(known.error_code, "DATAPLANE.BACKEND_NOT_BUILT");
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
            let invalid = execute(
                "speed.run",
                br#"{"node":"node-b","protocol":"raw","backend":"socket","direction":"upload","duration_ms":10000,"warmup_ms":1000,"cooldown_ms":1000,"streams":null,"frame_size":64,"target_rate_bps":100000000000,"auto_tune":false,"latency_under_load":false,"cpus":null,"numa_node":null}"#,
                &storage,
            );
            assert_eq!(invalid.error_code, "CLI.INVALID_ARGUMENT");
            let valid = execute(
                "speed.run",
                br#"{"node":"node-b","protocol":"raw","backend":"dpdk","direction":"upload","duration_ms":10000,"warmup_ms":1000,"cooldown_ms":1000,"streams":null,"frame_size":64,"target_rate_bps":100000000000,"auto_tune":false,"latency_under_load":false,"cpus":null,"numa_node":null}"#,
                &storage,
            );
            assert_eq!(valid.error_code, "NODE.NOT_PAIRED");
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
