//! Node TLS stream 上層的 control framing、Protobuf contract 與協商規則。

#![forbid(unsafe_code)]

mod frame;
mod negotiation;
mod state;
mod trust;
mod wire;

pub use frame::{CONTROL_HEADER_BYTES, MAX_CONTROL_PAYLOAD_BYTES, decode_frame, encode_frame};
pub use negotiation::{
    CapabilityRange, NegotiatedCapability, ProtocolRange, negotiate_capabilities, negotiate_version,
};
pub use state::{NodeConnectionState, NodeStateMachine};
pub use trust::{TrustDecision, fingerprint_sha256, verify_identity};
pub use wire::*;
