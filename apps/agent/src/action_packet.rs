#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PacketAnalyzePayload {
    input: String,
    sample_one_in: Option<u32>,
}

pub(super) async fn execute_packet_analyze(
    payload: &[u8],
) -> Result<serde_json::Value, NetToolError> {
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
pub(super) struct PacketCaptureStopPayload {
    session_id: String,
}

fn default_capture_backend() -> String {
    "dpdk".to_owned()
}

#[allow(clippy::too_many_lines)]
pub(super) async fn execute_packet_capture(
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

    let request: PacketCaptureStartPayload = serde_json::from_slice(payload).map_err(|error| {
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

pub(super) fn execute_packet_stats(payload: &[u8]) -> Result<serde_json::Value, NetToolError> {
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

pub(super) fn execute_packet_connections(
    payload: &[u8],
) -> Result<serde_json::Value, NetToolError> {
    if !cfg!(target_os = "linux") {
        return Err(NetToolError::new(
            ErrorCode::Unsupported,
            "packet connection statistics require Linux procfs in this build",
            false,
        ));
    }
    let request: PacketConnectionsPayload = serde_json::from_slice(payload).map_err(|error| {
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
            let word = u32::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16).map_err(
                |_| {
                    NetToolError::new(
                        ErrorCode::ProbeFailed,
                        format!("invalid IPv6 in {path}"),
                        false,
                    )
                },
            )?;
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
