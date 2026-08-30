//! Compatibility socket speed engine 與 UDP measurement protocol。

#![forbid(unsafe_code)]

mod accelerated;
mod auth;
mod config;
mod pacing;
mod result;
mod session;
mod socket_udp;
mod tcp;
mod udp;

pub use accelerated::{
    AcceleratedBackend, AcceleratedExecutionRequest, AcceleratedExecutionResult,
    AcceleratedSpeedExecutor, execute_with,
};
pub use auth::{
    MAX_AUTHORIZATION_TAG_BYTES, MIN_AUTHORIZATION_TAG_BYTES, authorization_tag_matches,
    validate_authorization_tag,
};
pub use config::SpeedRunRequest;
pub use pacing::{
    BatchPacer, PacingPolicy, PacingStrategy, RampObservation, UdpRateMode, find_loss_threshold,
};
pub use result::{BidirectionalUdpResult, LatencyComparison, UdpDirectionResult};
pub use session::{BarrierPeer, MeasurementWindow, SpeedTestLifecycle, SpeedTestPhase};
pub use socket_udp::{
    UDP_FLAG_AUTH, UDP_FLAG_END, UdpReceiverConfig, UdpReceiverResult, UdpSenderConfig,
    UdpSenderResult, run_udp_receiver, run_udp_sender,
};
pub use tcp::{
    AuthorizedTcpReceiverConfig, AuthorizedTcpSenderConfig, TcpRunConfig, TcpRunResult,
    run_authorized_tcp_receiver, run_authorized_tcp_sender, run_tcp_receiver, run_tcp_sender,
};
pub use udp::{
    BoundedUdpSequenceTracker, UDP_COMPACT_HEADER_BYTES, UDP_SEQUENCE_WINDOW_SIZE,
    UDP_SPEED_HEADER_BYTES, UdpCompactHeader, UdpJitterTracker, UdpSequenceStats,
    UdpSequenceTracker, UdpSpeedHeader,
};
