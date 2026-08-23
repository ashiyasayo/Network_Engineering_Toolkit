//! Agent 本機 IPC 的 length-prefixed Protobuf wire contract。

#![forbid(unsafe_code)]

use prost::Message;

/// 目前支援的 Agent protocol major。
pub const PROTOCOL_MAJOR: u32 = 1;
/// 目前支援的 Agent protocol minor。
pub const PROTOCOL_MINOR: u32 = 0;
/// 單一 frame 最大 payload，避免惡意本機 client 耗盡記憶體。
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Agent protocol envelope。
#[derive(Clone, PartialEq, Message)]
pub struct AgentEnvelope {
    /// Protocol major。
    #[prost(uint32, tag = "1")]
    pub protocol_major: u32,
    /// Protocol minor。
    #[prost(uint32, tag = "2")]
    pub protocol_minor: u32,
    /// 呼叫端產生的 request ID。
    #[prost(string, tag = "3")]
    pub request_id: String,
    /// Envelope payload。
    #[prost(oneof = "agent_envelope::Payload", tags = "10, 11")]
    pub payload: Option<agent_envelope::Payload>,
}

/// Envelope 的 payload variants。
pub mod agent_envelope {
    use super::{ActionRequest, ActionResponse};
    use prost::Oneof;

    /// Request 或 response；事件訂閱會在後續 session milestone 加入。
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Payload {
        /// Action request。
        #[prost(message, tag = "10")]
        Request(ActionRequest),
        /// Action response。
        #[prost(message, tag = "11")]
        Response(ActionResponse),
    }
}

/// Action request wire representation。
#[derive(Clone, PartialEq, Message)]
pub struct ActionRequest {
    /// Action registry 名稱。
    #[prost(string, tag = "1")]
    pub action: String,
    /// UTF-8 JSON payload；Protobuf 負責 envelope 相容性與 framing。
    #[prost(bytes = "vec", tag = "2")]
    pub payload_json: Vec<u8>,
    /// 冪等操作 ID；空字串代表未提供。
    #[prost(string, tag = "3")]
    pub operation_id: String,
    /// 是否只產生 dry-run plan。
    #[prost(bool, tag = "4")]
    pub dry_run: bool,
}

/// Action response wire representation。
#[derive(Clone, PartialEq, Message)]
pub struct ActionResponse {
    /// 執行是否成功。
    #[prost(bool, tag = "1")]
    pub success: bool,
    /// UTF-8 JSON result。
    #[prost(bytes = "vec", tag = "2")]
    pub data_json: Vec<u8>,
    /// 穩定錯誤代碼；成功時為空字串。
    #[prost(string, tag = "3")]
    pub error_code: String,
    /// 給人閱讀的錯誤訊息。
    #[prost(string, tag = "4")]
    pub error_message: String,
    /// 是否適合重試。
    #[prost(bool, tag = "5")]
    pub retryable: bool,
}

/// 將 envelope 編碼為 big-endian u32 length-prefixed frame。
///
/// # Errors
///
/// Envelope 編碼結果超過 [`MAX_FRAME_BYTES`] 時回傳錯誤文字。
pub fn encode_frame(envelope: &AgentEnvelope) -> Result<Vec<u8>, String> {
    let payload = envelope.encode_to_vec();
    if payload.len() > MAX_FRAME_BYTES {
        return Err("agent frame exceeds maximum size".to_owned());
    }
    let length =
        u32::try_from(payload.len()).map_err(|_| "agent frame length overflow".to_owned())?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// 解碼不含四位元組 length prefix 的 Protobuf payload。
///
/// # Errors
///
/// Payload 過大、Protobuf 無效或 protocol major 不相容時回傳錯誤文字。
pub fn decode_payload(payload: &[u8]) -> Result<AgentEnvelope, String> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err("agent frame exceeds maximum size".to_owned());
    }
    let envelope = AgentEnvelope::decode(payload)
        .map_err(|error| format!("invalid agent protobuf: {error}"))?;
    if envelope.protocol_major != PROTOCOL_MAJOR {
        return Err(format!(
            "unsupported agent protocol major: {}",
            envelope.protocol_major
        ));
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::{
        ActionRequest, AgentEnvelope, PROTOCOL_MAJOR, PROTOCOL_MINOR, agent_envelope,
        decode_payload, encode_frame,
    };
    use prost::Message;

    #[test]
    fn frame_round_trip_preserves_request() {
        let envelope = AgentEnvelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id: "request-1".to_owned(),
            payload: Some(agent_envelope::Payload::Request(ActionRequest {
                action: "system.health".to_owned(),
                payload_json: b"{}".to_vec(),
                operation_id: String::new(),
                dry_run: false,
            })),
        };
        let frame = encode_frame(&envelope).expect("small message must encode");
        let decoded = decode_payload(&frame[4..]).expect("encoded message must decode");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn rejects_incompatible_major() {
        let envelope = AgentEnvelope {
            protocol_major: 99,
            protocol_minor: 0,
            request_id: String::new(),
            payload: None,
        };
        assert!(decode_payload(&envelope.encode_to_vec()).is_err());
    }
}
