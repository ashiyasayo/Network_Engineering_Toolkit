#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CancelPayload {
    session_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpeedHistoryPayload {
    limit: Option<u32>,
    #[serde(default)]
    format: Option<String>,
}

pub(super) fn execute_history(
    payload: &[u8],
    storage: &Storage,
) -> Result<serde_json::Value, NetToolError> {
    let request: SpeedHistoryPayload = serde_json::from_slice(payload).map_err(|error| {
        NetToolError::new(
            ErrorCode::InvalidArgument,
            format!("invalid speed history payload: {error}"),
            false,
        )
    })?;
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
            serde_json::to_value(sessions).map_err(|error| storage_error(error.to_string()))
        })
}

#[cfg(test)]
pub(super) fn validate_request(
    payload: &[u8],
    storage: &Storage,
) -> Result<serde_json::Value, NetToolError> {
    let mut request = parse_speed_payload(payload)?;
    request.validate()?;
    resolve_accelerated_pci(&mut request)?;
    request.validate()?;
    validate_socket_speed_options(&request)?;
    let node = storage
        .resolve_trusted_node(&request.node)?
        .ok_or_else(|| {
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
}

pub(super) async fn execute_cancel(
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

#[allow(clippy::too_many_lines)]
pub(super) async fn execute_speed(
    payload: &[u8],
    runtime: &AgentRuntime,
) -> Result<serde_json::Value, NetToolError> {
    let mut request = parse_speed_payload(payload)?;
    request.validate()?;
    resolve_accelerated_pci(&mut request)?;
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

pub(super) fn utc_timestamp() -> String {
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
    let remote = serde_json::from_slice::<serde_json::Value>(&remote_result.result_json).map_err(
        |error| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                format!("remote bidirectional result JSON is invalid: {error}"),
                false,
            )
        },
    )?;
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
            "raw download receiver is not attached",
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
    let sender = serde_json::from_slice::<serde_json::Value>(&remote_result.result_json).map_err(
        |error| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                format!("remote sender result JSON is invalid: {error}"),
                false,
            )
        },
    )?;
    Ok(json!({
        "session_id": hex_node_id(prepared.session_id),
        "sender": sender,
        "receiver": receiver,
    }))
}

#[allow(clippy::too_many_lines)]
async fn run_upload_sender(
    request: &SpeedRunRequest,
    destination: SocketAddr,
    udp_socket: Option<&tokio::net::UdpSocket>,
    prepared: &nettool_node::PreparedRemoteSpeedSession,
) -> Result<serde_json::Value, NetToolError> {
    match request.protocol {
        nettool_domain::SpeedProtocol::Raw => {
            let pci = request.accelerated_pci_address.clone().ok_or_else(|| {
                NetToolError::new(ErrorCode::InvalidArgument, "raw DPDK request is missing PCI BDF", false)
            })?;
            let destination_mac = request.remote_mac_address.clone().ok_or_else(|| {
                NetToolError::new(ErrorCode::InvalidArgument, "raw DPDK request is missing remote MAC", false)
            })?;
            let frame_size = request.frame_size.unwrap_or(64);
            let bits_per_packet = u64::from(frame_size).saturating_mul(8).max(1);
            let packets = request
                .target_rate_bps
                .unwrap_or(0)
                .saturating_mul(request.duration_ms)
                .checked_div(bits_per_packet.saturating_mul(1_000).max(1))
                .unwrap_or(1)
                .max(1);
            let queue_plan = native_speed_queue_plan(&pci)?;
            let profile = RawGeneratorProfile {
                ethernet_size: frame_size,
                network: GeneratorNetwork::Ipv4,
                transport: GeneratorTransport::Udp,
                source_ips: IpRange { start: "192.0.2.1".parse().unwrap(), end: "192.0.2.1".parse().unwrap() },
                destination_ips: IpRange { start: "198.51.100.1".parse().unwrap(), end: "198.51.100.1".parse().unwrap() },
                source_ports: PortRange { start: 10_000, end: 10_000 },
                destination_ports: PortRange { start: 20_000, end: 20_000 },
                flow_count: 1,
                packet_rate: packets,
            };
            let template = profile.template_bytes_with_destination_mac(&destination_mac)?;
            let result = tokio::task::spawn_blocking(move || {
                nettool_backend_dpdk::execute_native_tx(
                    &nettool_backend_dpdk::NativeDpdkExecutionRequest {
                        pci_address: pci,
                        frame_size,
                        packets,
                        queue_plan,
                        frame_template: template,
                    },
                )
            })
            .await
            .map_err(|_| NetToolError::new(ErrorCode::SpeedFailed, "native DPDK TX task panicked", false))??;
            Ok(json!({
                "backend":"dpdk",
                "transmitted_packets":result.transmitted_packets,
                "hardware": {
                    "received_packets": result.hardware.received_packets,
                    "transmitted_packets": result.hardware.transmitted_packets,
                    "received_bytes": result.hardware.received_bytes,
                    "transmitted_bytes": result.hardware.transmitted_bytes,
                    "missed_packets": result.hardware.missed_packets,
                    "receive_errors": result.hardware.receive_errors,
                    "transmit_errors": result.hardware.transmit_errors,
                    "rx_mbuf_failures": result.hardware.rx_mbuf_failures
                },
                "xstats": result.xstats.iter().map(|stat| json!({"name":stat.name,"value":stat.value})).collect::<Vec<_>>()
            }))
        }
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
                        datagram_bytes: usize::from(request.frame_size.unwrap_or(1_200)).max(64),
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
    }
}

pub(super) fn native_speed_queue_plan(pci: &str) -> Result<nettool_backend_dpdk::QueuePlan, NetToolError> {
    let report = nettool_backend_dpdk::probe_environment()?;
    let nic = report.nics.iter().find(|nic| nic.pci_address.as_deref() == Some(pci)).ok_or_else(|| {
        NetToolError::new(ErrorCode::PreflightFailed, "native DPDK PCI BDF was not found", false)
    })?;
    nettool_backend_dpdk::plan_queues(
        nic.numa_node.ok_or_else(|| NetToolError::new(ErrorCode::PreflightFailed, "native DPDK NUMA node is unknown", false))?,
        NicQueueCapacity {
            receive: u16::try_from(nic.rx_queues.unwrap_or(0)).map_err(|_| NetToolError::new(ErrorCode::PreflightFailed, "native DPDK RX queue count is too large", false))?,
            transmit: u16::try_from(nic.tx_queues.unwrap_or(0)).map_err(|_| NetToolError::new(ErrorCode::PreflightFailed, "native DPDK TX queue count is too large", false))?,
        },
        &[DataPlaneCpu { logical_id: 0, numa_node: nic.numa_node.unwrap_or(0) }],
        1,
        QueueSelection::Auto,
    )
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

pub(super) fn parse_node_id(value: &str) -> Result<[u8; 16], NetToolError> {
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
