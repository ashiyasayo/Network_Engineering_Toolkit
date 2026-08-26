//! Node test session coordinator、dynamic port 與 idempotent operations。

use getrandom::fill as random_fill;
use nettool_error::{ErrorCode, NetToolError};
use nettool_node_protocol::{MAX_CONTROL_PAYLOAD_BYTES, NodeConnectionState, TestResult};
use nettool_resource::{
    ReservationRequest, ResourceClaim, ResourceKey, ResourceManager, ResourceMode,
};
use nettool_speed::{
    AuthorizedTcpReceiverConfig, AuthorizedTcpSenderConfig, BarrierPeer, SpeedTestLifecycle,
    TcpRunConfig, UdpReceiverConfig, UdpSenderConfig,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpListener, UdpSocket};

#[path = "session_prepare.rs"]
mod session_prepare;

/// Scheduler 到點後唯一取得的 authorized socket receiver worker。
pub enum PreparedSocketReceiver {
    /// TCP listener 與每-stream authorization config。
    Tcp(TcpListener, AuthorizedTcpReceiverConfig),
    /// UDP socket 與 AUTH bootstrap receiver config。
    Udp(UdpSocket, UdpReceiverConfig),
}

/// Scheduler 到點後唯一取得的 authorized socket sender worker。
pub enum PreparedSocketSender {
    /// TCP sender 設定與 initiator receiver endpoint。
    Tcp(AuthorizedTcpSenderConfig, SocketAddr),
    /// UDP sender socket、設定與 initiator receiver endpoint。
    Udp(UdpSocket, UdpSenderConfig, SocketAddr),
}

/// Scheduler 到點後同時取得雙向 receiver 與 sender worker。
pub enum PreparedSocketBidirectional {
    /// TCP listener、sender 設定與遠端 receiver endpoint。
    Tcp(
        TcpListener,
        AuthorizedTcpReceiverConfig,
        AuthorizedTcpSenderConfig,
        SocketAddr,
    ),
    /// UDP socket、receiver/sender 設定與遠端 receiver endpoint。
    Udp(UdpSocket, UdpReceiverConfig, UdpSenderConfig, SocketAddr),
}

/// TCP socket test 的 prepare request。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareTcpRequest {
    /// 128-bit session ID。
    pub session_id: [u8; 16],
    /// Mutating operation ID。
    pub operation_id: String,
    /// 預期的來源 Node ID。
    pub source_node_id: [u8; 16],
    /// 允許的來源 IP。
    pub source_address: IpAddr,
    /// Receiver bind address；port 必須為零以要求動態配置。
    pub bind_address: SocketAddr,
    /// TCP engine 設定。
    pub config: TcpRunConfig,
    /// Authorization context lifetime。
    pub authorization_ttl_seconds: u64,
}

/// TCP sender 的 prepare request；資料 endpoint 由 initiator 在 Prepare 前 bind。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareTcpSenderRequest {
    /// 128-bit session ID。
    pub session_id: [u8; 16],
    /// Mutating operation ID。
    pub operation_id: String,
    /// 本機 Node ID，供 receiver authorization context 綁定。
    pub source_node_id: [u8; 16],
    /// 本機 sender address。
    pub source_address: IpAddr,
    /// Initiator receiver endpoint。
    pub destination: SocketAddr,
    /// TCP engine 設定。
    pub config: TcpRunConfig,
    /// Authorization context lifetime。
    pub authorization_ttl_seconds: u64,
}

/// UDP sender 的 prepare request；sender source port 由本端 dynamic bind。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareUdpSenderRequest {
    /// 128-bit session ID。
    pub session_id: [u8; 16],
    /// Mutating operation ID。
    pub operation_id: String,
    /// 本機 Node ID。
    pub source_node_id: [u8; 16],
    /// 本機 sender bind address。
    pub source_address: IpAddr,
    /// Initiator receiver endpoint。
    pub destination: SocketAddr,
    /// UDP stream ID。
    pub stream_id: u32,
    /// Sender datagram bytes。
    pub datagram_bytes: usize,
    /// Measurement duration。
    pub measurement_milliseconds: u64,
    /// Optional fixed target rate.
    pub target_bits_per_second: Option<u64>,
    /// Authorization context lifetime。
    pub authorization_ttl_seconds: u64,
}

/// TCP bidirectional test 的 prepare request。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareTcpBidirectionalRequest {
    /// 128-bit session ID。
    pub session_id: [u8; 16],
    /// Mutating operation ID。
    pub operation_id: String,
    /// 本機 Node ID。
    pub source_node_id: [u8; 16],
    /// 本機 receiver bind address。
    pub source_address: IpAddr,
    /// Receiver listener bind address。
    pub bind_address: SocketAddr,
    /// Initiator receiver endpoint；sender 將連線至此 endpoint。
    pub destination: SocketAddr,
    /// TCP engine 設定。
    pub config: TcpRunConfig,
    /// Authorization context lifetime。
    pub authorization_ttl_seconds: u64,
}

/// UDP bidirectional test 的 prepare request。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareUdpBidirectionalRequest {
    /// 128-bit session ID。
    pub session_id: [u8; 16],
    /// Mutating operation ID。
    pub operation_id: String,
    /// Initiator Node ID。
    pub source_node_id: [u8; 16],
    /// Initiator sender source endpoint。
    pub source_address: SocketAddr,
    /// 本機 UDP receiver/sender bind address。
    pub bind_address: IpAddr,
    /// Initiator receiver endpoint。
    pub destination: SocketAddr,
    /// UDP stream ID。
    pub stream_id: u32,
    /// Datagram bytes。
    pub datagram_bytes: usize,
    /// Measurement duration。
    pub measurement_milliseconds: u64,
    /// Optional fixed target rate。
    pub target_bits_per_second: Option<u64>,
    /// Authorization context lifetime。
    pub authorization_ttl_seconds: u64,
}

/// Prepare 後可安全回傳給遠端 Node 的資料。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrepareTcpResponse {
    /// Session ID。
    pub session_id: [u8; 16],
    /// Dynamic data port。
    pub data_port: u16,
    /// 隨機 session-scoped authorization tag。
    pub authorization_tag: String,
    /// Authorization 到期 epoch 秒數。
    pub expires_at_unix_seconds: u64,
    /// Session state，成功 prepare 必須為 `TEST_READY`。
    pub state: NodeConnectionState,
}

/// UDP socket test 的 prepare request。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareUdpRequest {
    /// 128-bit session ID。
    pub session_id: [u8; 16],
    /// Mutating operation ID。
    pub operation_id: String,
    /// 預期的來源 Node ID。
    pub source_node_id: [u8; 16],
    /// 授權的 sender IP 與 dynamic source port。
    pub source_address: SocketAddr,
    /// Receiver bind address；port 必須為零。
    pub bind_address: SocketAddr,
    /// UDP stream ID。
    pub stream_id: u32,
    /// Receiver 最大 datagram bytes。
    pub maximum_datagram_bytes: usize,
    /// Receiver idle timeout。
    pub idle_timeout_milliseconds: u64,
    /// Authorization context lifetime。
    pub authorization_ttl_seconds: u64,
}

/// UDP prepare response。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrepareUdpResponse {
    /// Session ID。
    pub session_id: [u8; 16],
    /// Dynamic UDP destination port。
    pub data_port: u16,
    /// 隨機 session-scoped authorization tag。
    pub authorization_tag: String,
    /// Authorization 到期 epoch 秒數。
    pub expires_at_unix_seconds: u64,
    /// Session state。
    pub state: NodeConnectionState,
}

/// Data-plane connection 的授權邊界。
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DataPlaneAuthorization {
    /// Session ID。
    pub session_id: [u8; 16],
    /// 來源 Node ID。
    pub source_node_id: [u8; 16],
    /// 來源 address。
    pub source_address: IpAddr,
    /// 必須匹配的來源 port；TCP listener 為 `None`，UDP 為 dynamic sender port。
    pub source_port: Option<u16>,
    /// Receiver address。
    pub destination_address: IpAddr,
    /// Protocol registry name。
    pub protocol: String,
    /// Dynamic destination port。
    pub destination_port: u16,
    /// Cryptographically random tag。
    pub authorization_tag: String,
    /// 到期 epoch 秒數。
    pub expires_at_unix_seconds: u64,
}

/// Incoming data-plane connection 提供的完整 authorization context。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataPlaneAttempt<'a> {
    /// Session ID。
    pub session_id: [u8; 16],
    /// 已通過 control-plane TLS identity 驗證的來源 Node ID。
    pub source_node_id: [u8; 16],
    /// 實際來源 endpoint。
    pub source_address: SocketAddr,
    /// 實際 destination endpoint。
    pub destination_address: SocketAddr,
    /// Data-plane protocol registry name。
    pub protocol: &'a str,
    /// Session-scoped authorization tag。
    pub authorization_tag: &'a str,
    /// 驗證時的 epoch 秒數。
    pub now_unix_seconds: u64,
}

struct TcpSession {
    response: PrepareTcpResponse,
    authorization: DataPlaneAuthorization,
    config: TcpRunConfig,
    listener: Option<TcpListener>,
    state: NodeConnectionState,
    reservation_id: String,
    lifecycle: SpeedTestLifecycle,
    sender_destination: Option<SocketAddr>,
    sender_config: Option<TcpRunConfig>,
}

struct UdpSession {
    response: PrepareUdpResponse,
    authorization: DataPlaneAuthorization,
    socket: Option<UdpSocket>,
    stream_id: u32,
    maximum_datagram_bytes: usize,
    idle_timeout_milliseconds: u64,
    state: NodeConnectionState,
    reservation_id: String,
    lifecycle: SpeedTestLifecycle,
    sender_destination: Option<SocketAddr>,
    sender_config: Option<UdpSenderConfig>,
}

enum SessionMut<'a> {
    Tcp(&'a mut TcpSession),
    Udp(&'a mut UdpSession),
}

impl SessionMut<'_> {
    fn authorization(&self) -> &DataPlaneAuthorization {
        match self {
            Self::Tcp(session) => &session.authorization,
            Self::Udp(session) => &session.authorization,
        }
    }

    fn state(&self) -> NodeConnectionState {
        match self {
            Self::Tcp(session) => session.state,
            Self::Udp(session) => session.state,
        }
    }

    fn set_state(&mut self, state: NodeConnectionState) {
        match self {
            Self::Tcp(session) => session.state = state,
            Self::Udp(session) => session.state = state,
        }
    }

    fn lifecycle(&mut self) -> &mut SpeedTestLifecycle {
        match self {
            Self::Tcp(session) => &mut session.lifecycle,
            Self::Udp(session) => &mut session.lifecycle,
        }
    }

    fn reservation_id(&self) -> &str {
        match self {
            Self::Tcp(session) => &session.reservation_id,
            Self::Udp(session) => &session.reservation_id,
        }
    }

    fn close_endpoint(&mut self) {
        match self {
            Self::Tcp(session) => {
                session.listener.take();
            }
            Self::Udp(session) => {
                session.socket.take();
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OperationRecord {
    PrepareTcp {
        request: PrepareTcpRequest,
        response: PrepareTcpResponse,
    },
    PrepareTcpSender {
        request: PrepareTcpSenderRequest,
        response: PrepareTcpResponse,
    },
    PrepareTcpBidirectional {
        request: PrepareTcpBidirectionalRequest,
        response: PrepareTcpResponse,
    },
    PrepareUdpSender {
        request: PrepareUdpSenderRequest,
        response: PrepareUdpResponse,
    },
    PrepareUdpBidirectional {
        request: PrepareUdpBidirectionalRequest,
        response: PrepareUdpResponse,
    },
    PrepareUdp {
        request: PrepareUdpRequest,
        response: PrepareUdpResponse,
    },
    Start {
        session_id: [u8; 16],
        start_at_unix_nanoseconds: u64,
        state: NodeConnectionState,
    },
    Stop {
        session_id: [u8; 16],
        state: NodeConnectionState,
    },
}

/// Agent-owned Node session runtime authority。
#[derive(Default)]
pub struct SessionCoordinator {
    tcp_sessions: HashMap<[u8; 16], TcpSession>,
    udp_sessions: HashMap<[u8; 16], UdpSession>,
    operations: HashMap<String, OperationRecord>,
    results: HashMap<[u8; 16], TestResult>,
    pending_results: HashMap<[u8; 16], TestResult>,
    resources: ResourceManager,
}

impl SessionCoordinator {
    /// 建立 coordinator。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn session_exists(&self, session_id: [u8; 16]) -> bool {
        self.tcp_sessions.contains_key(&session_id) || self.udp_sessions.contains_key(&session_id)
    }

    fn session_state(&self, session_id: [u8; 16]) -> Option<NodeConnectionState> {
        self.tcp_sessions
            .get(&session_id)
            .map(|session| session.state)
            .or_else(|| {
                self.udp_sessions
                    .get(&session_id)
                    .map(|session| session.state)
            })
    }

    fn session_mut(&mut self, session_id: [u8; 16]) -> Option<SessionMut<'_>> {
        if let Some(session) = self.tcp_sessions.get_mut(&session_id) {
            return Some(SessionMut::Tcp(session));
        }
        self.udp_sessions.get_mut(&session_id).map(SessionMut::Udp)
    }

    /// 確認遠端 READY 並排定共同開始時間；不會提前切換為 running。
    ///
    /// # Errors
    ///
    /// Operation ID 衝突、session 不存在、authorization 已逾期、時間無效或狀態不是 `TEST_READY` 時回傳錯誤。
    pub fn start(
        &mut self,
        session_id: [u8; 16],
        operation_id: &str,
        start_at_unix_nanoseconds: u64,
        now_unix_nanoseconds: u64,
    ) -> Result<NodeConnectionState, NetToolError> {
        if let Some(record) = self.operations.get(operation_id) {
            return matching_start(record, session_id, start_at_unix_nanoseconds);
        }
        let mut session = self.session_mut(session_id).ok_or_else(session_missing)?;
        let now_unix_seconds = now_unix_nanoseconds / 1_000_000_000;
        if session.authorization().expires_at_unix_seconds < now_unix_seconds {
            return Err(NetToolError::new(
                ErrorCode::AuthorizationExpired,
                "data-plane authorization expired",
                false,
            ));
        }
        if session.state() != NodeConnectionState::TestReady {
            return Err(invalid_state("session is not ready"));
        }
        if start_at_unix_nanoseconds / 1_000_000_000
            > session.authorization().expires_at_unix_seconds
        {
            return Err(NetToolError::new(
                ErrorCode::AuthorizationExpired,
                "scheduled start exceeds data-plane authorization lifetime",
                false,
            ));
        }
        session.lifecycle().mark_ready(BarrierPeer::Remote)?;
        session
            .lifecycle()
            .schedule_start(start_at_unix_nanoseconds, now_unix_nanoseconds)?;
        let state = session.state();
        self.operations.insert(
            operation_id.to_owned(),
            OperationRecord::Start {
                session_id,
                start_at_unix_nanoseconds,
                state,
            },
        );
        Ok(state)
    }

    /// 到達排定時間後由本機 scheduler 啟動 warmup/data plane。
    ///
    /// # Errors
    ///
    /// Session 不存在、尚未排程或指定時間尚未到達時回傳錯誤。
    pub fn begin_scheduled(
        &mut self,
        session_id: [u8; 16],
        now_unix_nanoseconds: u64,
    ) -> Result<NodeConnectionState, NetToolError> {
        let mut session = self.session_mut(session_id).ok_or_else(session_missing)?;
        if session.state() != NodeConnectionState::TestReady {
            return Err(invalid_state("session is not waiting for scheduled start"));
        }
        if now_unix_nanoseconds / 1_000_000_000 > session.authorization().expires_at_unix_seconds {
            return Err(NetToolError::new(
                ErrorCode::AuthorizationExpired,
                "data-plane authorization expired before scheduled start",
                false,
            ));
        }
        session.lifecycle().begin_warmup(now_unix_nanoseconds)?;
        session.set_state(NodeConnectionState::Running);
        Ok(session.state())
    }

    /// 到達共同 start time 後原子切換 Running 並取走唯一 receiver endpoint。
    ///
    /// # Errors
    ///
    /// Session 尚未到期、狀態錯誤或 endpoint 已被另一 worker 取得時回傳錯誤。
    pub fn begin_and_take_receiver(
        &mut self,
        session_id: [u8; 16],
        now_unix_nanoseconds: u64,
    ) -> Result<PreparedSocketReceiver, NetToolError> {
        if self
            .tcp_sessions
            .get(&session_id)
            .is_some_and(|session| session.sender_destination.is_some())
            || self
                .udp_sessions
                .get(&session_id)
                .is_some_and(|session| session.sender_destination.is_some())
        {
            return Err(invalid_state("session is a TCP sender"));
        }
        self.begin_scheduled(session_id, now_unix_nanoseconds)?;
        if self.tcp_sessions.contains_key(&session_id) {
            let (listener, config) = self.take_tcp_listener(session_id)?;
            return Ok(PreparedSocketReceiver::Tcp(listener, config));
        }
        let (socket, config) = self.take_udp_socket(session_id)?;
        Ok(PreparedSocketReceiver::Udp(socket, config))
    }

    /// 到達排定時間後原子切換 Running 並取走唯一 TCP sender worker。
    ///
    /// # Errors
    ///
    /// Session 不是 TCP sender、尚未到期或 sender 已被另一 worker 取得時回傳錯誤。
    pub fn begin_and_take_sender(
        &mut self,
        session_id: [u8; 16],
        now_unix_nanoseconds: u64,
    ) -> Result<PreparedSocketSender, NetToolError> {
        let tcp_sender = self
            .tcp_sessions
            .get(&session_id)
            .is_some_and(|session| session.sender_destination.is_some());
        let udp_sender = self
            .udp_sessions
            .get(&session_id)
            .is_some_and(|session| session.sender_destination.is_some());
        if !tcp_sender && !udp_sender {
            return Err(invalid_state("session is not a socket sender"));
        }
        self.begin_scheduled(session_id, now_unix_nanoseconds)?;
        if tcp_sender {
            self.take_tcp_sender(session_id)
        } else {
            self.take_udp_sender(session_id)
        }
    }

    /// 到達排定時間後同時取走雙向 socket worker。
    ///
    /// # Errors
    ///
    /// Session 不是 bidirectional、尚未到期或 endpoint 已被取得時回傳錯誤。
    pub fn begin_and_take_bidirectional(
        &mut self,
        session_id: [u8; 16],
        now_unix_nanoseconds: u64,
    ) -> Result<PreparedSocketBidirectional, NetToolError> {
        let tcp = self.tcp_sessions.get(&session_id).is_some_and(|session| {
            session.sender_destination.is_some() && session.sender_config.is_some()
        });
        let udp = self.udp_sessions.get(&session_id).is_some_and(|session| {
            session.sender_destination.is_some() && session.sender_config.is_some()
        });
        if !tcp && !udp {
            return Err(invalid_state("session is not bidirectional"));
        }
        self.begin_scheduled(session_id, now_unix_nanoseconds)?;
        if tcp {
            self.take_tcp_bidirectional(session_id)
        } else {
            self.take_udp_bidirectional(session_id)
        }
    }

    /// 取消 prepared/running session；重送相同 operation 為冪等成功。
    ///
    /// # Errors
    ///
    /// Operation ID 衝突、session 不存在或狀態不可取消時回傳錯誤。
    pub fn stop(
        &mut self,
        session_id: [u8; 16],
        operation_id: &str,
    ) -> Result<NodeConnectionState, NetToolError> {
        if let Some(record) = self.operations.get(operation_id) {
            return matching_stop(record, session_id);
        }
        if self.session_state(session_id) == Some(NodeConnectionState::Canceled) {
            self.operations.insert(
                operation_id.to_owned(),
                OperationRecord::Stop {
                    session_id,
                    state: NodeConnectionState::Canceled,
                },
            );
            return Ok(NodeConnectionState::Canceled);
        }
        let reservation_id = {
            let mut session = self.session_mut(session_id).ok_or_else(session_missing)?;
            if !matches!(
                session.state(),
                NodeConnectionState::TestReady
                    | NodeConnectionState::Running
                    | NodeConnectionState::Finalizing
            ) {
                return Err(invalid_state(
                    "session cannot be canceled from current state",
                ));
            }
            let reservation_id = session.reservation_id().to_owned();
            session.set_state(NodeConnectionState::Canceled);
            session.close_endpoint();
            reservation_id
        };
        self.resources.begin_release(&reservation_id)?;
        self.resources.finish_release(&reservation_id)?;
        self.operations.insert(
            operation_id.to_owned(),
            OperationRecord::Stop {
                session_id,
                state: NodeConnectionState::Canceled,
            },
        );
        Ok(NodeConnectionState::Canceled)
    }

    /// 將已完成 worker 的 session 原子推進至 Completed、釋放資源並保存可重取結果。
    ///
    /// Result JSON 必須是帶非空 `schema_version` 的 object；checksum 固定為完整 JSON bytes 的
    /// SHA-256。相同 session 與相同 bytes 重送為冪等成功。
    ///
    /// # Errors
    ///
    /// Session、狀態、JSON schema、結果大小或資源釋放失敗時回傳錯誤。
    pub fn complete(
        &mut self,
        session_id: [u8; 16],
        result_json: Vec<u8>,
    ) -> Result<TestResult, NetToolError> {
        validate_result_json(&result_json)?;
        if let Some(existing) = self.results.get(&session_id) {
            return if existing.result_json == result_json {
                Ok(existing.clone())
            } else {
                Err(operation_conflict())
            };
        }
        let result = TestResult {
            session_id: session_id.to_vec(),
            checksum: Sha256::digest(&result_json).to_vec(),
            result_json,
        };
        let reservation_id = {
            let mut session = self.session_mut(session_id).ok_or_else(session_missing)?;
            if !matches!(
                session.state(),
                NodeConnectionState::Running | NodeConnectionState::Finalizing
            ) {
                return Err(invalid_state("only a running session can complete"));
            }
            if session.state() == NodeConnectionState::Running {
                session.set_state(NodeConnectionState::Finalizing);
            }
            session.reservation_id().to_owned()
        };
        if let Some(pending) = self.pending_results.get(&session_id) {
            if *pending != result {
                return Err(operation_conflict());
            }
        } else {
            self.pending_results.insert(session_id, result.clone());
        }
        self.resources.begin_release(&reservation_id)?;
        self.resources.finish_release(&reservation_id)?;
        {
            let mut session = self.session_mut(session_id).ok_or_else(session_missing)?;
            session.close_endpoint();
            session.set_state(NodeConnectionState::Completed);
        }
        self.pending_results.remove(&session_id);
        self.results.insert(session_id, result.clone());
        Ok(result)
    }

    /// 將 prepared/running/finalizing session 以 versioned failure result 結束並釋放資源。
    ///
    /// 相同 session 與相同 result bytes 重送為冪等成功；敏感 tag 不應放入 result JSON。
    ///
    /// # Errors
    ///
    /// Session、狀態、JSON schema、結果大小或資源釋放失敗時回傳錯誤。
    pub fn fail(
        &mut self,
        session_id: [u8; 16],
        result_json: Vec<u8>,
    ) -> Result<TestResult, NetToolError> {
        validate_result_json(&result_json)?;
        if let Some(existing) = self.results.get(&session_id) {
            return if existing.result_json == result_json {
                Ok(existing.clone())
            } else {
                Err(operation_conflict())
            };
        }
        let result = TestResult {
            session_id: session_id.to_vec(),
            checksum: Sha256::digest(&result_json).to_vec(),
            result_json,
        };
        let reservation_id = {
            let mut session = self.session_mut(session_id).ok_or_else(session_missing)?;
            if !matches!(
                session.state(),
                NodeConnectionState::TestReady
                    | NodeConnectionState::Running
                    | NodeConnectionState::Finalizing
            ) {
                return Err(invalid_state("session cannot transition to failed"));
            }
            session.set_state(NodeConnectionState::Finalizing);
            session.reservation_id().to_owned()
        };
        if let Some(pending) = self.pending_results.get(&session_id) {
            if *pending != result {
                return Err(operation_conflict());
            }
        } else {
            self.pending_results.insert(session_id, result.clone());
        }
        self.resources.begin_release(&reservation_id)?;
        self.resources.finish_release(&reservation_id)?;
        {
            let mut session = self.session_mut(session_id).ok_or_else(session_missing)?;
            session.close_endpoint();
            session.set_state(NodeConnectionState::Failed);
        }
        self.pending_results.remove(&session_id);
        self.results.insert(session_id, result.clone());
        Ok(result)
    }

    /// 取得已完成 session 的 immutable result；可安全重試。
    ///
    /// # Errors
    ///
    /// Session 不存在或尚未完成時回傳錯誤；尚未完成的錯誤可重試。
    pub fn test_result(&self, session_id: [u8; 16]) -> Result<TestResult, NetToolError> {
        if let Some(result) = self.results.get(&session_id) {
            return Ok(result.clone());
        }
        if self.session_exists(session_id) {
            return Err(NetToolError::new(
                ErrorCode::InvalidState,
                "test result is not ready",
                true,
            ));
        }
        Err(session_missing())
    }

    /// 取得 prepared listener 與 config 交給 Speed Engine；每個 session 只能取得一次。
    ///
    /// # Errors
    ///
    /// Session 不存在、尚未 start 或 listener 已被取得時回傳錯誤。
    pub fn take_tcp_listener(
        &mut self,
        session_id: [u8; 16],
    ) -> Result<(TcpListener, AuthorizedTcpReceiverConfig), NetToolError> {
        let session = self
            .tcp_sessions
            .get_mut(&session_id)
            .ok_or_else(session_missing)?;
        if session.sender_destination.is_some() {
            return Err(invalid_state("session is a TCP sender"));
        }
        if session.state != NodeConnectionState::Running {
            return Err(invalid_state("session is not running"));
        }
        let listener = session
            .listener
            .take()
            .ok_or_else(|| invalid_state("session listener was already consumed"))?;
        Ok((
            listener,
            AuthorizedTcpReceiverConfig {
                expected_streams: session.config.streams,
                session_id,
                authorization_tag: session.authorization.authorization_tag.clone(),
            },
        ))
    }

    /// 取得已 Running 的 TCP sender 設定；每個 session 只能取得一次。
    ///
    /// # Errors
    ///
    /// Session 不存在、尚未 Running、不是 sender 或已被另一 worker 取得時回傳錯誤。
    pub fn take_tcp_sender(
        &mut self,
        session_id: [u8; 16],
    ) -> Result<PreparedSocketSender, NetToolError> {
        let session = self
            .tcp_sessions
            .get_mut(&session_id)
            .ok_or_else(session_missing)?;
        if session.state != NodeConnectionState::Running {
            return Err(invalid_state("session is not running"));
        }
        if session.sender_config.is_some() {
            return Err(invalid_state("session is bidirectional"));
        }
        let destination = session
            .sender_destination
            .take()
            .ok_or_else(|| invalid_state("session is not a TCP sender"))?;
        Ok(PreparedSocketSender::Tcp(
            AuthorizedTcpSenderConfig {
                run: session.config,
                session_id,
                authorization_tag: session.authorization.authorization_tag.clone(),
            },
            destination,
        ))
    }

    /// 取得 TCP bidirectional listener、receiver/sender config；只能取得一次。
    ///
    /// # Errors
    ///
    /// Session 不存在、尚未 Running 或 endpoint 已被取得時回傳錯誤。
    pub fn take_tcp_bidirectional(
        &mut self,
        session_id: [u8; 16],
    ) -> Result<PreparedSocketBidirectional, NetToolError> {
        let session = self
            .tcp_sessions
            .get_mut(&session_id)
            .ok_or_else(session_missing)?;
        if session.state != NodeConnectionState::Running {
            return Err(invalid_state("session is not running"));
        }
        let listener = session
            .listener
            .take()
            .ok_or_else(|| invalid_state("session listener was already consumed"))?;
        let destination = session
            .sender_destination
            .take()
            .ok_or_else(|| invalid_state("session is not bidirectional"))?;
        let run = session
            .sender_config
            .take()
            .ok_or_else(|| invalid_state("session sender configuration is missing"))?;
        let receiver = AuthorizedTcpReceiverConfig {
            expected_streams: session.config.streams,
            session_id,
            authorization_tag: session.authorization.authorization_tag.clone(),
        };
        let sender = AuthorizedTcpSenderConfig {
            run,
            session_id,
            authorization_tag: session.authorization.authorization_tag.clone(),
        };
        Ok(PreparedSocketBidirectional::Tcp(
            listener,
            receiver,
            sender,
            destination,
        ))
    }

    /// 取得 prepared UDP socket 與 endpoint-bound receiver config；只能取得一次。
    ///
    /// # Errors
    ///
    /// Session 不存在、protocol 不符、尚未 start 或 socket 已被取得時回傳錯誤。
    pub fn take_udp_socket(
        &mut self,
        session_id: [u8; 16],
    ) -> Result<(UdpSocket, UdpReceiverConfig), NetToolError> {
        let session = self
            .udp_sessions
            .get_mut(&session_id)
            .ok_or_else(session_missing)?;
        if session.sender_destination.is_some() {
            return Err(invalid_state("session is a UDP sender"));
        }
        if session.state != NodeConnectionState::Running {
            return Err(invalid_state("session is not running"));
        }
        let socket = session
            .socket
            .take()
            .ok_or_else(|| invalid_state("session UDP socket was already consumed"))?;
        let source_port = session
            .authorization
            .source_port
            .ok_or_else(|| invalid_state("UDP authorization is missing its source port"))?;
        let config = UdpReceiverConfig {
            session_id,
            stream_id: session.stream_id,
            expected_source: SocketAddr::new(session.authorization.source_address, source_port),
            maximum_datagram_bytes: session.maximum_datagram_bytes,
            idle_timeout_milliseconds: session.idle_timeout_milliseconds,
            authorization_tag: session.authorization.authorization_tag.clone(),
        };
        Ok((socket, config))
    }

    /// 取得已 Running 的 UDP sender socket 與設定；每個 session 只能取得一次。
    ///
    /// # Errors
    ///
    /// Session 不存在、尚未 Running、不是 sender 或 endpoint 已被取得時回傳錯誤。
    pub fn take_udp_sender(
        &mut self,
        session_id: [u8; 16],
    ) -> Result<PreparedSocketSender, NetToolError> {
        let session = self
            .udp_sessions
            .get_mut(&session_id)
            .ok_or_else(session_missing)?;
        if session.state != NodeConnectionState::Running {
            return Err(invalid_state("session is not running"));
        }
        if session.sender_config.is_none() {
            return Err(invalid_state("session is not a UDP sender"));
        }
        let destination = session
            .sender_destination
            .take()
            .ok_or_else(|| invalid_state("session is not a UDP sender"))?;
        let socket = session
            .socket
            .take()
            .ok_or_else(|| invalid_state("session sender socket was already consumed"))?;
        let config = session
            .sender_config
            .take()
            .ok_or_else(|| invalid_state("session sender configuration is missing"))?;
        Ok(PreparedSocketSender::Udp(socket, config, destination))
    }

    /// 取得 UDP bidirectional socket 與 receiver/sender config；只能取得一次。
    ///
    /// # Errors
    ///
    /// Session 不存在、尚未 Running 或 endpoint 已被取得時回傳錯誤。
    pub fn take_udp_bidirectional(
        &mut self,
        session_id: [u8; 16],
    ) -> Result<PreparedSocketBidirectional, NetToolError> {
        let session = self
            .udp_sessions
            .get_mut(&session_id)
            .ok_or_else(session_missing)?;
        if session.state != NodeConnectionState::Running {
            return Err(invalid_state("session is not running"));
        }
        let socket = session
            .socket
            .take()
            .ok_or_else(|| invalid_state("session UDP socket was already consumed"))?;
        let source_port = session
            .authorization
            .source_port
            .ok_or_else(|| invalid_state("UDP authorization is missing its source port"))?;
        let receiver = UdpReceiverConfig {
            session_id,
            stream_id: session.stream_id,
            expected_source: SocketAddr::new(session.authorization.source_address, source_port),
            maximum_datagram_bytes: session.maximum_datagram_bytes,
            idle_timeout_milliseconds: session.idle_timeout_milliseconds,
            authorization_tag: session.authorization.authorization_tag.clone(),
        };
        let destination = session
            .sender_destination
            .take()
            .ok_or_else(|| invalid_state("session is not bidirectional"))?;
        let sender = session
            .sender_config
            .take()
            .ok_or_else(|| invalid_state("session sender configuration is missing"))?;
        Ok(PreparedSocketBidirectional::Udp(
            socket,
            receiver,
            sender,
            destination,
        ))
    }

    /// 取得 session authorization context。
    #[must_use]
    pub fn authorization(&self, session_id: [u8; 16]) -> Option<&DataPlaneAuthorization> {
        self.tcp_sessions
            .get(&session_id)
            .map(|session| &session.authorization)
            .or_else(|| {
                self.udp_sessions
                    .get(&session_id)
                    .map(|session| &session.authorization)
            })
    }

    /// 取得 prepare response，用於 Agent restart 後回復狀態呈現。
    #[must_use]
    pub fn prepared_response(&self, session_id: [u8; 16]) -> Option<&PrepareTcpResponse> {
        self.tcp_sessions
            .get(&session_id)
            .map(|session| &session.response)
    }

    /// 取得 UDP prepare response。
    #[must_use]
    pub fn prepared_udp_response(&self, session_id: [u8; 16]) -> Option<&PrepareUdpResponse> {
        self.udp_sessions
            .get(&session_id)
            .map(|session| &session.response)
    }
}

/// 驗證 incoming data-plane connection 是否符合 session-scoped authorization。
#[must_use]
pub fn authorize_data_plane(
    context: &DataPlaneAuthorization,
    attempt: &DataPlaneAttempt<'_>,
) -> bool {
    context.session_id == attempt.session_id
        && context.source_node_id == attempt.source_node_id
        && context.source_address == attempt.source_address.ip()
        && context
            .source_port
            .is_none_or(|port| port == attempt.source_address.port())
        && context.destination_address == attempt.destination_address.ip()
        && context.destination_port == attempt.destination_address.port()
        && context.protocol == attempt.protocol
        && constant_time_eq(
            context.authorization_tag.as_bytes(),
            attempt.authorization_tag.as_bytes(),
        )
        && attempt.now_unix_seconds <= context.expires_at_unix_seconds
}

fn constant_time_eq(expected: &[u8], candidate: &[u8]) -> bool {
    if expected.len() != candidate.len() {
        return false;
    }
    expected
        .iter()
        .zip(candidate)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn validate_prepare(request: &PrepareTcpRequest) -> Result<(), NetToolError> {
    if request.operation_id.trim().is_empty() {
        return Err(invalid("operation ID is required"));
    }
    if request.bind_address.port() != 0 {
        return Err(invalid(
            "data-plane bind port must be zero for dynamic allocation",
        ));
    }
    if !(10..=3600).contains(&request.authorization_ttl_seconds) {
        return Err(invalid(
            "authorization TTL must be between 10 seconds and one hour",
        ));
    }
    request.config.validate()
}

fn validate_tcp_sender_prepare(request: &PrepareTcpSenderRequest) -> Result<(), NetToolError> {
    if request.operation_id.trim().is_empty() {
        return Err(invalid("operation ID is required"));
    }
    if request.destination.port() == 0 {
        return Err(invalid("TCP sender destination port must be non-zero"));
    }
    if !(10..=3600).contains(&request.authorization_ttl_seconds) {
        return Err(invalid(
            "authorization TTL must be between 10 seconds and one hour",
        ));
    }
    request.config.validate()
}

fn validate_tcp_bidirectional_prepare(
    request: &PrepareTcpBidirectionalRequest,
) -> Result<(), NetToolError> {
    if request.operation_id.trim().is_empty() {
        return Err(invalid("operation ID is required"));
    }
    if request.bind_address.port() != 0 || request.destination.port() == 0 {
        return Err(invalid("TCP bidirectional endpoints are invalid"));
    }
    if !(10..=3600).contains(&request.authorization_ttl_seconds) {
        return Err(invalid(
            "authorization TTL must be between 10 seconds and one hour",
        ));
    }
    request.config.validate()
}

fn validate_udp_prepare(request: &PrepareUdpRequest) -> Result<(), NetToolError> {
    if request.operation_id.trim().is_empty() {
        return Err(invalid("operation ID is required"));
    }
    if request.bind_address.port() != 0 {
        return Err(invalid(
            "data-plane bind port must be zero for dynamic allocation",
        ));
    }
    if request.source_address.port() == 0 {
        return Err(invalid("UDP source port must be allocated before prepare"));
    }
    if !(10..=3600).contains(&request.authorization_ttl_seconds) {
        return Err(invalid(
            "authorization TTL must be between 10 seconds and one hour",
        ));
    }
    UdpReceiverConfig {
        session_id: request.session_id,
        stream_id: request.stream_id,
        expected_source: request.source_address,
        maximum_datagram_bytes: request.maximum_datagram_bytes,
        idle_timeout_milliseconds: request.idle_timeout_milliseconds,
        authorization_tag: "prepare-validation".to_owned(),
    }
    .validate()
}

fn validate_udp_sender_prepare(request: &PrepareUdpSenderRequest) -> Result<(), NetToolError> {
    if request.operation_id.trim().is_empty() {
        return Err(invalid("operation ID is required"));
    }
    if request.destination.port() == 0 {
        return Err(invalid("UDP sender destination port must be non-zero"));
    }
    if !(10..=3600).contains(&request.authorization_ttl_seconds) {
        return Err(invalid(
            "authorization TTL must be between 10 seconds and one hour",
        ));
    }
    UdpSenderConfig {
        session_id: request.session_id,
        stream_id: request.stream_id,
        datagram_bytes: request.datagram_bytes,
        measurement_milliseconds: request.measurement_milliseconds,
        target_bits_per_second: request.target_bits_per_second,
        maximum_packets_per_burst: 32,
        authorization_tag: "prepare-validation".to_owned(),
    }
    .validate()
}

fn validate_udp_bidirectional_prepare(
    request: &PrepareUdpBidirectionalRequest,
) -> Result<(), NetToolError> {
    if request.operation_id.trim().is_empty() {
        return Err(invalid("operation ID is required"));
    }
    if request.source_address.port() == 0 || request.destination.port() == 0 {
        return Err(invalid("UDP bidirectional endpoints are invalid"));
    }
    if !(10..=3600).contains(&request.authorization_ttl_seconds) {
        return Err(invalid(
            "authorization TTL must be between 10 seconds and one hour",
        ));
    }
    UdpSenderConfig {
        session_id: request.session_id,
        stream_id: request.stream_id,
        datagram_bytes: request.datagram_bytes,
        measurement_milliseconds: request.measurement_milliseconds,
        target_bits_per_second: request.target_bits_per_second,
        maximum_packets_per_burst: 32,
        authorization_tag: "prepare-validation".to_owned(),
    }
    .validate()
}

fn validate_result_json(result_json: &[u8]) -> Result<(), NetToolError> {
    if result_json.is_empty() || result_json.len() > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(invalid("test result JSON is empty or exceeds 1 MiB"));
    }
    let value: serde_json::Value = serde_json::from_slice(result_json).map_err(|error| {
        NetToolError::new(
            ErrorCode::ProtocolInvalid,
            format!("test result JSON is invalid: {error}"),
            false,
        )
    })?;
    if value
        .as_object()
        .and_then(|object| object.get("schema_version"))
        .and_then(serde_json::Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid(
            "test result JSON must contain a non-empty schema_version",
        ));
    }
    Ok(())
}

fn random_tag() -> Result<String, NetToolError> {
    let mut bytes = [0_u8; 32];
    random_fill(&mut bytes).map_err(|error| {
        NetToolError::new(
            ErrorCode::RandomFailed,
            format!("secure random generation failed: {error}"),
            true,
        )
    })?;
    let mut tag = String::with_capacity(64);
    for byte in bytes {
        // 寫入 String 不會發生 fmt I/O 錯誤。
        let _ = write!(tag, "{byte:02x}");
    }
    Ok(tag)
}

fn hex_session_id(session_id: [u8; 16]) -> String {
    let mut value = String::with_capacity(32);
    for byte in session_id {
        // 寫入 String 不會發生 fmt I/O 錯誤。
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn matching_start(
    record: &OperationRecord,
    session_id: [u8; 16],
    start_at_unix_nanoseconds: u64,
) -> Result<NodeConnectionState, NetToolError> {
    match record {
        OperationRecord::Start {
            session_id: stored,
            start_at_unix_nanoseconds: stored_start,
            state,
        } if *stored == session_id && *stored_start == start_at_unix_nanoseconds => Ok(*state),
        _ => Err(operation_conflict()),
    }
}

fn matching_stop(
    record: &OperationRecord,
    session_id: [u8; 16],
) -> Result<NodeConnectionState, NetToolError> {
    match record {
        OperationRecord::Stop {
            session_id: stored,
            state,
        } if *stored == session_id => Ok(*state),
        _ => Err(operation_conflict()),
    }
}

fn invalid(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}
fn invalid_state(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidState, message, false)
}
fn operation_conflict() -> NetToolError {
    NetToolError::new(
        ErrorCode::OperationConflict,
        "operation ID was already used by a different request",
        false,
    )
}
fn session_missing() -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, "session does not exist", false)
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::SpeedFailed,
        format!("dynamic data port allocation failed: {error}"),
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        DataPlaneAttempt, DataPlaneAuthorization, PrepareTcpRequest,
        PrepareUdpBidirectionalRequest, PrepareUdpRequest, PrepareUdpSenderRequest,
        PreparedSocketBidirectional, PreparedSocketReceiver, PreparedSocketSender,
        SessionCoordinator, authorize_data_plane,
    };
    use nettool_node_protocol::NodeConnectionState;
    use nettool_speed::{
        TcpRunConfig, UdpReceiverConfig, UdpSenderConfig, run_udp_receiver, run_udp_sender,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::UdpSocket;

    #[test]
    fn final_result_requires_versioned_json() {
        assert!(super::validate_result_json(br#"{"schema_version":"1.0"}"#).is_ok());
        assert!(super::validate_result_json(br#"{"bytes":42}"#).is_err());
        assert!(super::validate_result_json(b"not-json").is_err());
    }

    #[test]
    fn authorization_binds_every_context_field_and_expiration() {
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let context = DataPlaneAuthorization {
            session_id: [1; 16],
            source_node_id: [2; 16],
            source_address: address,
            source_port: None,
            destination_address: address,
            protocol: "tcp".to_owned(),
            destination_port: 5000,
            authorization_tag: "secret".to_owned(),
            expires_at_unix_seconds: 100,
        };
        let valid = DataPlaneAttempt {
            session_id: [1; 16],
            source_node_id: [2; 16],
            source_address: SocketAddr::new(address, 1234),
            destination_address: SocketAddr::new(address, 5000),
            protocol: "tcp",
            authorization_tag: "secret",
            now_unix_seconds: 100,
        };
        assert!(authorize_data_plane(&context, &valid));
        assert!(!authorize_data_plane(
            &context,
            &DataPlaneAttempt {
                authorization_tag: "wrong",
                ..valid
            }
        ));
        assert!(!authorize_data_plane(
            &context,
            &DataPlaneAttempt {
                now_unix_seconds: 101,
                ..valid
            }
        ));
        assert!(!authorize_data_plane(
            &context,
            &DataPlaneAttempt {
                protocol: "udp",
                ..valid
            }
        ));
    }

    #[tokio::test]
    #[ignore = "requires permission to bind a loopback socket"]
    async fn prepare_start_stop_are_idempotent_and_use_dynamic_port() {
        let mut coordinator = SessionCoordinator::new();
        let request = PrepareTcpRequest {
            session_id: [1; 16],
            operation_id: "prepare-1".to_owned(),
            source_node_id: [2; 16],
            source_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            config: TcpRunConfig {
                streams: 1,
                payload_bytes: 4096,
                warmup_milliseconds: 0,
                measurement_milliseconds: 100,
            },
            authorization_ttl_seconds: 30,
        };
        let first = coordinator
            .prepare_tcp(request.clone(), 100)
            .await
            .expect("prepare succeeds");
        let duplicate = coordinator
            .prepare_tcp(request.clone(), 101)
            .await
            .expect("duplicate succeeds");
        assert_eq!(duplicate, first);
        let mut conflicting = request;
        conflicting.authorization_ttl_seconds = 31;
        assert!(coordinator.prepare_tcp(conflicting, 101).await.is_err());
        assert_ne!(first.data_port, 0);
        assert_eq!(
            coordinator
                .start([1; 16], "start-1", 110_000_000_000, 109_000_000_000)
                .expect("start is scheduled"),
            NodeConnectionState::TestReady
        );
        assert_eq!(
            coordinator
                .start([1; 16], "start-1", 110_000_000_000, 109_500_000_000)
                .expect("duplicate start succeeds"),
            NodeConnectionState::TestReady
        );
        assert!(
            coordinator
                .begin_scheduled([1; 16], 109_999_999_999)
                .is_err()
        );
        let config = match coordinator
            .begin_and_take_receiver([1; 16], 110_000_000_000)
            .expect("scheduled start and receiver handoff succeed")
        {
            PreparedSocketReceiver::Tcp(_listener, config) => config,
            PreparedSocketReceiver::Udp(_, _) => panic!("expected TCP receiver"),
        };
        assert_eq!(config.expected_streams, 1);
        assert_eq!(config.authorization_tag, first.authorization_tag);
        assert!(
            coordinator
                .begin_and_take_receiver([1; 16], 110_000_000_000)
                .is_err()
        );
        assert_eq!(
            coordinator.stop([1; 16], "stop-1").expect("stop succeeds"),
            NodeConnectionState::Canceled
        );
        assert_eq!(
            coordinator
                .stop([1; 16], "stop-1")
                .expect("duplicate stop succeeds"),
            NodeConnectionState::Canceled
        );
        assert_eq!(
            coordinator
                .stop([1; 16], "stop-2")
                .expect("cancellation with a new operation ID is idempotent"),
            NodeConnectionState::Canceled
        );
    }

    #[tokio::test]
    #[ignore = "requires permission to bind loopback UDP sockets"]
    async fn udp_prepare_uses_dynamic_port_endpoint_auth_and_shared_lifecycle() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
        let source_address = sender.local_addr().expect("source");
        let mut coordinator = SessionCoordinator::new();
        let request = PrepareUdpRequest {
            session_id: [3; 16],
            operation_id: "udp-prepare-1".to_owned(),
            source_node_id: [4; 16],
            source_address,
            bind_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            stream_id: 7,
            maximum_datagram_bytes: 1500,
            idle_timeout_milliseconds: 1000,
            authorization_ttl_seconds: 30,
        };
        let first = coordinator
            .prepare_udp(request.clone(), 100)
            .await
            .expect("prepare");
        assert_eq!(
            coordinator.prepare_udp(request, 101).await.expect("repeat"),
            first
        );
        assert_ne!(first.data_port, 0);
        let authorization = coordinator.authorization([3; 16]).expect("authorization");
        assert_eq!(authorization.protocol, "udp");
        assert_eq!(authorization.source_port, Some(source_address.port()));
        coordinator
            .start([3; 16], "udp-start-1", 110_000_000_000, 109_000_000_000)
            .expect("schedule");
        coordinator
            .begin_scheduled([3; 16], 110_000_000_000)
            .expect("start");
        let (socket, config) = coordinator.take_udp_socket([3; 16]).expect("socket");
        assert_eq!(socket.local_addr().expect("local").port(), first.data_port);
        assert_eq!(config.expected_source, source_address);
        assert_eq!(config.stream_id, 7);
        assert!(coordinator.take_udp_socket([3; 16]).is_err());
        let receive_task = tokio::spawn(async move { run_udp_receiver(&socket, config).await });
        let send_result = run_udp_sender(
            &sender,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), first.data_port),
            UdpSenderConfig {
                session_id: [3; 16],
                stream_id: 7,
                datagram_bytes: 256,
                measurement_milliseconds: 100,
                target_bits_per_second: Some(1_000_000),
                maximum_packets_per_burst: 32,
                authorization_tag: first.authorization_tag.clone(),
            },
        )
        .await
        .expect("send");
        let receive_result = receive_task.await.expect("task").expect("receive");
        assert_eq!(receive_result.rx_packets, send_result.tx_packets);
        assert_eq!(receive_result.sequence.lost, 0);
        assert!(receive_result.graceful_end);
        let result_json = serde_json::to_vec(&serde_json::json!({
            "schema_version":"1.0",
            "sender":send_result,
            "receiver":receive_result
        }))
        .expect("result JSON");
        let completed = coordinator
            .complete([3; 16], result_json.clone())
            .expect("complete");
        assert_eq!(completed.result_json, result_json);
        assert_eq!(coordinator.test_result([3; 16]).expect("query"), completed);
        assert_eq!(
            coordinator
                .complete([3; 16], result_json)
                .expect("complete retry"),
            completed
        );
        assert!(coordinator.stop([3; 16], "udp-stop-1").is_err());
    }

    #[tokio::test]
    #[ignore = "requires permission to bind loopback UDP sockets"]
    async fn udp_sender_prepare_handoffs_authorized_worker_once() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("receiver");
        let destination = receiver.local_addr().expect("destination");
        let mut coordinator = SessionCoordinator::new();
        let response = coordinator
            .prepare_udp_sender(
                PrepareUdpSenderRequest {
                    session_id: [5; 16],
                    operation_id: "udp-sender-prepare".to_owned(),
                    source_node_id: [6; 16],
                    source_address: Ipv4Addr::LOCALHOST.into(),
                    destination,
                    stream_id: 0,
                    datagram_bytes: 256,
                    measurement_milliseconds: 100,
                    target_bits_per_second: None,
                    authorization_ttl_seconds: 30,
                },
                100,
            )
            .await
            .expect("prepare sender");
        assert_eq!(response.data_port, 0);
        let source_port = coordinator
            .authorization([5; 16])
            .expect("authorization")
            .source_port
            .expect("source port");
        coordinator
            .start(
                [5; 16],
                "udp-sender-start",
                110_000_000_000,
                109_000_000_000,
            )
            .expect("schedule");
        let worker = coordinator
            .begin_and_take_sender([5; 16], 110_000_000_000)
            .expect("sender handoff");
        let result = match worker {
            PreparedSocketSender::Udp(socket, config, destination) => {
                assert_eq!(socket.local_addr().expect("local").port(), source_port);
                assert_eq!(config.session_id, [5; 16]);
                assert_eq!(destination, receiver.local_addr().expect("destination"));
                run_udp_sender(&socket, destination, config)
                    .await
                    .expect("send")
            }
            PreparedSocketSender::Tcp(_, _) => panic!("expected UDP sender"),
        };
        assert!(result.tx_packets > 0);
        let mut buffer = [0_u8; 512];
        let (_bytes, source) = receiver.recv_from(&mut buffer).await.expect("AUTH");
        assert_eq!(source.port(), source_port);
        assert!(
            coordinator
                .begin_and_take_sender([5; 16], 110_000_000_000)
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires permission to bind loopback UDP sockets"]
    async fn udp_bidirectional_prepare_runs_both_directions() {
        let local_socket = UdpSocket::bind("127.0.0.1:0").await.expect("local socket");
        let local_address = local_socket.local_addr().expect("local address");
        let mut coordinator = SessionCoordinator::new();
        let response = coordinator
            .prepare_udp_bidirectional(
                PrepareUdpBidirectionalRequest {
                    session_id: [8; 16],
                    operation_id: "udp-bidi-prepare".to_owned(),
                    source_node_id: [9; 16],
                    source_address: local_address,
                    bind_address: Ipv4Addr::LOCALHOST.into(),
                    destination: local_address,
                    stream_id: 0,
                    datagram_bytes: 256,
                    measurement_milliseconds: 100,
                    target_bits_per_second: None,
                    authorization_ttl_seconds: 30,
                },
                100,
            )
            .await
            .expect("prepare");
        coordinator
            .start([8; 16], "udp-bidi-start", 110_000_000_000, 109_000_000_000)
            .expect("schedule");
        let worker = coordinator
            .begin_and_take_bidirectional([8; 16], 110_000_000_000)
            .expect("handoff");
        let PreparedSocketBidirectional::Udp(
            remote_socket,
            remote_receiver,
            remote_sender,
            remote_destination,
        ) = worker
        else {
            panic!("expected UDP bidirectional worker");
        };
        let remote_source = remote_socket.local_addr().expect("remote source");
        let local_receiver = UdpReceiverConfig {
            session_id: [8; 16],
            stream_id: 0,
            expected_source: remote_source,
            maximum_datagram_bytes: 256,
            idle_timeout_milliseconds: 2_000,
            authorization_tag: remote_sender.authorization_tag.clone(),
        };
        let local_sender = UdpSenderConfig {
            session_id: [8; 16],
            stream_id: 0,
            datagram_bytes: 256,
            measurement_milliseconds: 100,
            target_bits_per_second: None,
            maximum_packets_per_burst: 32,
            authorization_tag: remote_sender.authorization_tag.clone(),
        };
        let (remote_result, local_result) = tokio::join!(
            async {
                let (receiver, sender) = tokio::join!(
                    run_udp_receiver(&remote_socket, remote_receiver),
                    run_udp_sender(&remote_socket, remote_destination, remote_sender),
                );
                (
                    receiver.expect("remote receive"),
                    sender.expect("remote send"),
                )
            },
            async {
                let (receiver, sender) = tokio::join!(
                    run_udp_receiver(&local_socket, local_receiver),
                    run_udp_sender(&local_socket, remote_source, local_sender),
                );
                (
                    receiver.expect("local receive"),
                    sender.expect("local send"),
                )
            }
        );
        assert!(response.data_port != 0);
        assert!(remote_result.0.rx_packets > 0);
        assert!(remote_result.1.tx_packets > 0);
        assert!(local_result.0.rx_packets > 0);
        assert!(local_result.1.tx_packets > 0);
    }
}
