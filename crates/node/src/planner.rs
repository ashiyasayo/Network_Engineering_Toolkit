use nettool_domain::{Direction, SpeedProtocol};
use nettool_error::{ErrorCode, NetToolError};
use nettool_node_protocol::{CapabilityMessage, PrepareTest};
use nettool_speed::SpeedRunRequest;
use std::collections::BTreeSet;

/// Capability registry：TCP speed。
pub const CAPABILITY_TCP_SPEED: u32 = 0x0001;
/// Capability registry：UDP speed。
pub const CAPABILITY_UDP_SPEED: u32 = 0x0002;
/// Capability registry：bidirectional test。
pub const CAPABILITY_BIDIRECTIONAL: u32 = 0x0003;
/// Capability registry：latency measurement。
pub const CAPABILITY_LATENCY: u32 = 0x0004;
/// Capability registry：DPDK。
pub const CAPABILITY_DPDK: u32 = 0x0005;
/// Capability registry：`AF_XDP`。
pub const CAPABILITY_AF_XDP: u32 = 0x0006;
/// Capability registry：Windows RIO。
pub const CAPABILITY_RIO: u32 = 0x0007;
/// Capability registry：jumbo frame。
pub const CAPABILITY_JUMBO_FRAME: u32 = 0x000B;
/// Capability registry：raw packet generator。
pub const CAPABILITY_RAW_PACKET_GENERATOR: u32 = 0x000C;
/// Capability registry：latency under load。
pub const CAPABILITY_LATENCY_UNDER_LOAD: u32 = 0x000D;

const REQUIRED_CAPABILITY_VERSION: u32 = 1;

/// 已驗證 capability 並可直接送入 Node control plane 的 session plan。
#[derive(Clone, Debug, PartialEq)]
pub struct SpeedSessionPlan {
    /// 這次執行要求的 capability IDs，已排序去重。
    pub required_capabilities: Vec<u32>,
    /// Wire-level prepare request。
    pub prepare: PrepareTest,
}

/// Initiator 在 remote Prepare 前已實際 bind 的 data-plane ports。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalDataPlanePorts {
    /// Initiator sender source port；UDP upload/bidirectional 必填。
    pub send: u16,
    /// Initiator receiver port；download/bidirectional socket test 必填。
    pub receive: u16,
}

/// 驗證 remote capabilities 並建立 wire `PrepareTest`。
///
/// `source_data_port` 必須先由本機 data-plane 動態 bind 取得；UDP 不能傳入零，避免
/// remote authorization 接受任意來源 port。Wire 中的零值 streams/frame/rate 只表示
/// protocol 定義的 auto/not-applicable，不會被當成量測結果。
///
/// # Errors
///
/// Speed request、operation/session ID、UDP source port 或 remote capability 無效時回傳錯誤。
pub fn plan_speed_session(
    request: &SpeedRunRequest,
    operation_id: &str,
    session_id: [u8; 16],
    local_ports: LocalDataPlanePorts,
    remote_capabilities: &[CapabilityMessage],
) -> Result<SpeedSessionPlan, NetToolError> {
    request.validate()?;
    if operation_id.trim().is_empty() || session_id == [0; 16] {
        return Err(invalid("speed operation and session IDs must be non-empty"));
    }
    let sends = matches!(
        request.direction,
        Direction::Upload | Direction::Bidirectional
    );
    let receives = matches!(
        request.direction,
        Direction::Download | Direction::Bidirectional
    );
    if request.protocol == SpeedProtocol::Udp && sends && local_ports.send == 0 {
        return Err(invalid(
            "UDP source data port must be dynamically allocated before prepare",
        ));
    }
    if request.protocol != SpeedProtocol::Raw && receives && local_ports.receive == 0 {
        return Err(invalid(
            "local receive data port must be dynamically allocated before prepare",
        ));
    }
    if request.protocol == SpeedProtocol::Raw && local_ports != LocalDataPlanePorts::default() {
        return Err(invalid("raw Ethernet does not use socket data ports"));
    }
    let required_capabilities = required_capabilities(request);
    validate_capabilities(&required_capabilities, remote_capabilities)?;
    Ok(SpeedSessionPlan {
        required_capabilities,
        prepare: PrepareTest {
            session_id: session_id.to_vec(),
            operation_id: operation_id.to_owned(),
            test_type: protocol_name(request.protocol).to_owned(),
            backend: request.backend.clone(),
            direction: direction_name(request.direction).to_owned(),
            duration_ms: request.duration_ms,
            warmup_ms: request.warmup_ms,
            cooldown_ms: request.cooldown_ms,
            streams: request.streams.map_or(0, u32::from),
            frame_size: request.frame_size.map_or(0, u32::from),
            payload_size: 0,
            target_rate_bps: request.target_rate_bps.unwrap_or(0),
            mtu: 0,
            source_data_port: u32::from(local_ports.send),
            receive_data_port: u32::from(local_ports.receive),
        },
    })
}

fn required_capabilities(request: &SpeedRunRequest) -> Vec<u32> {
    let mut required = BTreeSet::new();
    match request.protocol {
        SpeedProtocol::Tcp => {
            required.insert(CAPABILITY_TCP_SPEED);
        }
        SpeedProtocol::Udp => {
            required.insert(CAPABILITY_UDP_SPEED);
        }
        SpeedProtocol::Raw => {
            required.insert(CAPABILITY_RAW_PACKET_GENERATOR);
        }
    }
    if request.direction == Direction::Bidirectional {
        required.insert(CAPABILITY_BIDIRECTIONAL);
    }
    match request.backend.as_str() {
        "dpdk" => {
            required.insert(CAPABILITY_DPDK);
        }
        "af_xdp" => {
            required.insert(CAPABILITY_AF_XDP);
        }
        "rio" => {
            required.insert(CAPABILITY_RIO);
        }
        _ => {}
    }
    if request.frame_size.is_some_and(|size| size > 1_518) {
        required.insert(CAPABILITY_JUMBO_FRAME);
    }
    if request.latency_under_load {
        required.insert(CAPABILITY_LATENCY);
        required.insert(CAPABILITY_LATENCY_UNDER_LOAD);
    }
    required.into_iter().collect()
}

fn validate_capabilities(
    required: &[u32],
    remote: &[CapabilityMessage],
) -> Result<(), NetToolError> {
    let mut seen = BTreeSet::new();
    for capability in remote {
        if !seen.insert(capability.id) {
            return Err(protocol(
                "remote capability response contains duplicate IDs",
            ));
        }
        if capability.min_version == 0
            || capability.min_version > capability.max_version
            || capability.max_version == 0
        {
            return Err(protocol(
                "remote capability response contains an invalid version range",
            ));
        }
    }
    for required_id in required {
        let available = remote.iter().any(|capability| {
            capability.id == *required_id
                && capability.available
                && capability.min_version <= REQUIRED_CAPABILITY_VERSION
                && capability.max_version >= REQUIRED_CAPABILITY_VERSION
        });
        if !available {
            let mut error = NetToolError::new(
                ErrorCode::ProtocolIncompatible,
                "remote Node does not provide a required speed capability",
                false,
            );
            error
                .details
                .insert("capability_id".to_owned(), format!("0x{required_id:04X}"));
            return Err(error);
        }
    }
    Ok(())
}

const fn protocol_name(protocol: SpeedProtocol) -> &'static str {
    match protocol {
        SpeedProtocol::Tcp => "tcp",
        SpeedProtocol::Udp => "udp",
        SpeedProtocol::Raw => "raw",
    }
}

const fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Upload => "upload",
        Direction::Download => "download",
        Direction::Bidirectional => "bidirectional",
    }
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

fn protocol(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::ProtocolInvalid, message, false)
}

#[cfg(test)]
mod tests {
    use super::{
        CAPABILITY_BIDIRECTIONAL, CAPABILITY_DPDK, CAPABILITY_JUMBO_FRAME, CAPABILITY_LATENCY,
        CAPABILITY_LATENCY_UNDER_LOAD, CAPABILITY_RAW_PACKET_GENERATOR, CAPABILITY_UDP_SPEED,
        LocalDataPlanePorts, plan_speed_session,
    };
    use nettool_domain::{Direction, SpeedProtocol};
    use nettool_node_protocol::CapabilityMessage;
    use nettool_speed::SpeedRunRequest;

    fn capability(id: u32) -> CapabilityMessage {
        CapabilityMessage {
            id,
            min_version: 1,
            max_version: 1,
            available: true,
        }
    }

    fn raw_request() -> SpeedRunRequest {
        SpeedRunRequest {
            node: "node-b".to_owned(),
            protocol: SpeedProtocol::Raw,
            backend: "dpdk".to_owned(),
            direction: Direction::Bidirectional,
            duration_ms: 10_000,
            warmup_ms: 1_000,
            cooldown_ms: 1_000,
            streams: None,
            frame_size: Some(9_018),
            target_rate_bps: Some(100_000_000_000),
            auto_tune: false,
            latency_under_load: true,
            cpus: None,
            numa_node: None,
        }
    }

    #[test]
    fn maps_raw_request_to_typed_wire_plan() {
        let remote = [
            capability(CAPABILITY_BIDIRECTIONAL),
            capability(CAPABILITY_DPDK),
            capability(CAPABILITY_JUMBO_FRAME),
            capability(CAPABILITY_LATENCY),
            capability(CAPABILITY_RAW_PACKET_GENERATOR),
            capability(CAPABILITY_LATENCY_UNDER_LOAD),
        ];
        let plan = plan_speed_session(
            &raw_request(),
            "operation-1",
            [7; 16],
            LocalDataPlanePorts::default(),
            &remote,
        )
        .expect("plan");
        assert_eq!(plan.prepare.test_type, "raw");
        assert_eq!(plan.prepare.frame_size, 9_018);
        assert_eq!(plan.prepare.streams, 0);
        assert_eq!(plan.prepare.source_data_port, 0);
        assert_eq!(plan.required_capabilities.len(), 6);
    }

    #[test]
    fn rejects_missing_or_duplicate_remote_capabilities() {
        let request = raw_request();
        let missing = [capability(CAPABILITY_DPDK)];
        let error = plan_speed_session(
            &request,
            "operation-1",
            [7; 16],
            LocalDataPlanePorts::default(),
            &missing,
        )
        .expect_err("missing capability");
        assert!(error.details.contains_key("capability_id"));
        let duplicated = [capability(CAPABILITY_DPDK), capability(CAPABILITY_DPDK)];
        assert!(
            plan_speed_session(
                &request,
                "operation-1",
                [7; 16],
                LocalDataPlanePorts::default(),
                &duplicated
            )
            .is_err()
        );
    }

    #[test]
    fn udp_requires_bound_source_port_before_remote_prepare() {
        let mut request = raw_request();
        request.protocol = SpeedProtocol::Udp;
        request.backend = "socket".to_owned();
        request.direction = Direction::Upload;
        request.frame_size = None;
        request.latency_under_load = false;
        let remote = [capability(CAPABILITY_UDP_SPEED)];
        assert!(
            plan_speed_session(
                &request,
                "operation-1",
                [7; 16],
                LocalDataPlanePorts::default(),
                &remote
            )
            .is_err()
        );
        let plan = plan_speed_session(
            &request,
            "operation-1",
            [7; 16],
            LocalDataPlanePorts {
                send: 49_152,
                receive: 0,
            },
            &remote,
        )
        .expect("UDP plan");
        assert_eq!(plan.prepare.source_data_port, 49_152);
    }

    #[test]
    fn download_and_bidirectional_require_prebound_receiver() {
        let mut request = raw_request();
        request.protocol = SpeedProtocol::Udp;
        request.backend = "socket".to_owned();
        request.direction = Direction::Download;
        request.frame_size = None;
        request.latency_under_load = false;
        let remote = [capability(CAPABILITY_UDP_SPEED)];
        assert!(
            plan_speed_session(
                &request,
                "operation-1",
                [7; 16],
                LocalDataPlanePorts::default(),
                &remote
            )
            .is_err()
        );
        let plan = plan_speed_session(
            &request,
            "operation-1",
            [7; 16],
            LocalDataPlanePorts {
                send: 0,
                receive: 49_153,
            },
            &remote,
        )
        .expect("download plan");
        assert_eq!(plan.prepare.receive_data_port, 49_153);
    }
}
