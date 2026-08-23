//! Node control plane 的 Protobuf v1 baseline messages。

use prost::{Message, Oneof};

/// Application protocol major。
pub const PROTOCOL_MAJOR: u32 = 1;
/// Application protocol minor。
pub const PROTOCOL_MINOR: u32 = 1;

/// 所有 control messages 的 envelope。
#[derive(Clone, PartialEq, Message)]
pub struct Envelope {
    /// Protocol major。
    #[prost(uint32, tag = "1")]
    pub protocol_major: u32,
    /// Protocol minor。
    #[prost(uint32, tag = "2")]
    pub protocol_minor: u32,
    /// 128-bit request ID bytes。
    #[prost(bytes = "vec", tag = "3")]
    pub request_id: Vec<u8>,
    /// Typed message。
    #[prost(
        oneof = "envelope::ControlMessage",
        tags = "10,11,20,21,30,31,40,41,42,43,44,45,46,50,51,100"
    )]
    pub message: Option<envelope::ControlMessage>,
}

/// Envelope message variants。
pub mod envelope {
    use super::{
        CapabilityRequest, CapabilityResponse, HelloRequest, HelloResponse, Oneof, PairRequest,
        PairResponse, Ping, Pong, PrepareTest, PrepareTestResponse, ProtocolError, StartTest,
        StopTest, TestResult, TestResultRequest, TestStatus,
    };

    /// Protocol v1 control messages。
    #[derive(Clone, PartialEq, Oneof)]
    pub enum ControlMessage {
        /// Hello request。
        #[prost(message, tag = "10")]
        HelloRequest(HelloRequest),
        /// Hello response。
        #[prost(message, tag = "11")]
        HelloResponse(HelloResponse),
        /// Pair request。
        #[prost(message, tag = "20")]
        PairRequest(PairRequest),
        /// Pair response。
        #[prost(message, tag = "21")]
        PairResponse(PairResponse),
        /// Capability request。
        #[prost(message, tag = "30")]
        CapabilityRequest(CapabilityRequest),
        /// Capability response。
        #[prost(message, tag = "31")]
        CapabilityResponse(CapabilityResponse),
        /// Prepare test。
        #[prost(message, tag = "40")]
        PrepareTest(PrepareTest),
        /// Prepare response。
        #[prost(message, tag = "41")]
        PrepareTestResponse(PrepareTestResponse),
        /// Start test。
        #[prost(message, tag = "42")]
        StartTest(StartTest),
        /// Stop test。
        #[prost(message, tag = "43")]
        StopTest(StopTest),
        /// Test status。
        #[prost(message, tag = "44")]
        TestStatus(TestStatus),
        /// Test result。
        #[prost(message, tag = "45")]
        TestResult(TestResult),
        /// 可重試的 final result query。
        #[prost(message, tag = "46")]
        TestResultRequest(TestResultRequest),
        /// Heartbeat ping。
        #[prost(message, tag = "50")]
        Ping(Ping),
        /// Heartbeat pong。
        #[prost(message, tag = "51")]
        Pong(Pong),
        /// Stable error envelope。
        #[prost(message, tag = "100")]
        Error(ProtocolError),
    }
}

/// Initial identity/version request。
#[derive(Clone, PartialEq, Message)]
pub struct HelloRequest {
    /// 128-bit Node ID。
    #[prost(bytes = "vec", tag = "1")]
    pub node_id: Vec<u8>,
    /// Node 顯示名稱。
    #[prost(string, tag = "2")]
    pub node_name: String,
    /// 支援的最低 minor。
    #[prost(uint32, tag = "3")]
    pub min_minor: u32,
    /// 支援的最高 minor。
    #[prost(uint32, tag = "4")]
    pub max_minor: u32,
}

/// Negotiated version response。
#[derive(Clone, PartialEq, Message)]
pub struct HelloResponse {
    /// 選定的 minor。
    #[prost(uint32, tag = "1")]
    pub selected_minor: u32,
    /// Responder Node ID。
    #[prost(bytes = "vec", tag = "2")]
    pub node_id: Vec<u8>,
    /// Responder 顯示名稱。
    #[prost(string, tag = "3")]
    pub node_name: String,
}

/// User-confirmed pairing request。
#[derive(Clone, PartialEq, Message)]
pub struct PairRequest {
    /// Node ID。
    #[prost(bytes = "vec", tag = "1")]
    pub node_id: Vec<u8>,
    /// Identity public key DER bytes。
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: Vec<u8>,
}

/// Pairing decision。
#[derive(Clone, PartialEq, Message)]
pub struct PairResponse {
    /// 使用者是否確認信任。
    #[prost(bool, tag = "1")]
    pub trusted: bool,
    /// 完整 SHA-256 fingerprint。
    #[prost(string, tag = "2")]
    pub fingerprint: String,
}

/// Capability exchange request。
#[derive(Clone, PartialEq, Message)]
pub struct CapabilityRequest {}

/// Capability exchange response。
#[derive(Clone, PartialEq, Message)]
pub struct CapabilityResponse {
    /// 實際探測到的 capabilities。
    #[prost(message, repeated, tag = "1")]
    pub capabilities: Vec<CapabilityMessage>,
}

/// Capability wire model。
#[derive(Clone, PartialEq, Message)]
pub struct CapabilityMessage {
    /// Registry ID。
    #[prost(uint32, tag = "1")]
    pub id: u32,
    /// 最低版本。
    #[prost(uint32, tag = "2")]
    pub min_version: u32,
    /// 最高版本。
    #[prost(uint32, tag = "3")]
    pub max_version: u32,
    /// Runtime 是否實際可用。
    #[prost(bool, tag = "4")]
    pub available: bool,
}

/// Prepare test parameters。
#[derive(Clone, PartialEq, Message)]
pub struct PrepareTest {
    /// 128-bit session ID。
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
    /// 冪等 operation ID。
    #[prost(string, tag = "2")]
    pub operation_id: String,
    /// Test type registry name。
    #[prost(string, tag = "3")]
    pub test_type: String,
    /// Backend registry name。
    #[prost(string, tag = "4")]
    pub backend: String,
    /// Direction registry name。
    #[prost(string, tag = "5")]
    pub direction: String,
    /// Measurement milliseconds。
    #[prost(uint64, tag = "6")]
    pub duration_ms: u64,
    /// Warmup milliseconds。
    #[prost(uint64, tag = "7")]
    pub warmup_ms: u64,
    /// Cooldown milliseconds。
    #[prost(uint64, tag = "8")]
    pub cooldown_ms: u64,
    /// Parallel stream count。
    #[prost(uint32, tag = "9")]
    pub streams: u32,
    /// Frame bytes。
    #[prost(uint32, tag = "10")]
    pub frame_size: u32,
    /// Payload bytes。
    #[prost(uint32, tag = "11")]
    pub payload_size: u32,
    /// Target bits per second。
    #[prost(uint64, tag = "12")]
    pub target_rate_bps: u64,
    /// MTU bytes。
    #[prost(uint32, tag = "13")]
    pub mtu: u32,
    /// Sender 已配置的 dynamic source port；UDP endpoint authorization 必須比對。
    #[prost(uint32, tag = "14")]
    pub source_data_port: u32,
    /// Initiator 已配置的 receiver port；download/bidirectional 必須在 Prepare 前 bind。
    #[prost(uint32, tag = "15")]
    pub receive_data_port: u32,
}

/// Prepared data-plane endpoint。
#[derive(Clone, PartialEq, Message)]
pub struct PrepareTestResponse {
    /// 資源與資料平面是否就緒。
    #[prost(bool, tag = "1")]
    pub ready: bool,
    /// Dynamic data-plane port。
    #[prost(uint32, tag = "2")]
    pub data_port: u32,
    /// Session-scoped authorization tag。
    #[prost(string, tag = "3")]
    pub authorization_tag: String,
    /// Remote sender 綁定的 source port；UDP download/bidirectional authorization 必須比對。
    #[prost(uint32, tag = "4")]
    pub source_data_port: u32,
}

/// Synchronized test start。
#[derive(Clone, PartialEq, Message)]
pub struct StartTest {
    /// Session ID。
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
    /// 冪等 operation ID。
    #[prost(string, tag = "2")]
    pub operation_id: String,
    /// 雙方協調的 wall-clock 開始時間；duration 不可由此欄位計算。
    #[prost(uint64, tag = "3")]
    pub start_at_unix_nanoseconds: u64,
}

/// Idempotent stop/cancel request。
#[derive(Clone, PartialEq, Message)]
pub struct StopTest {
    /// Session ID。
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
    /// 冪等 operation ID。
    #[prost(string, tag = "2")]
    pub operation_id: String,
}

/// Session state update。
#[derive(Clone, PartialEq, Message)]
pub struct TestStatus {
    /// Session ID。
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
    /// Stable session state。
    #[prost(string, tag = "2")]
    pub state: String,
}

/// 依 session ID 可重試地取得 final result。
#[derive(Clone, PartialEq, Message)]
pub struct TestResultRequest {
    /// 128-bit session ID。
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
}

/// Final result bytes use a separately versioned JSON schema。
#[derive(Clone, PartialEq, Message)]
pub struct TestResult {
    /// Session ID。
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: Vec<u8>,
    /// Versioned JSON result bytes。
    #[prost(bytes = "vec", tag = "2")]
    pub result_json: Vec<u8>,
    /// Result/environment checksum。
    #[prost(bytes = "vec", tag = "3")]
    pub checksum: Vec<u8>,
}

/// Heartbeat request monotonic nonce。
#[derive(Clone, PartialEq, Message)]
pub struct Ping {
    /// Opaque nonce。
    #[prost(uint64, tag = "1")]
    pub nonce: u64,
}

/// Heartbeat response nonce。
#[derive(Clone, PartialEq, Message)]
pub struct Pong {
    /// Request nonce。
    #[prost(uint64, tag = "1")]
    pub nonce: u64,
}

/// Stable control error。
#[derive(Clone, PartialEq, Message)]
pub struct ProtocolError {
    /// Stable error code。
    #[prost(string, tag = "1")]
    pub code: String,
    /// Human-readable message。
    #[prost(string, tag = "2")]
    pub message: String,
    /// Retry hint。
    #[prost(bool, tag = "3")]
    pub retryable: bool,
}
