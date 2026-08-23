//! 12-byte NTCP control frame header。

use crate::Envelope;
use nettool_error::{ErrorCode, NetToolError};
use prost::Message;

const MAGIC: &[u8; 4] = b"NTCP";
const FRAMING_VERSION: u8 = 1;
/// 固定 control frame header bytes。
pub const CONTROL_HEADER_BYTES: usize = 12;
/// 第一版單一 control payload 上限 1 MiB。
pub const MAX_CONTROL_PAYLOAD_BYTES: usize = 1024 * 1024;

/// 將 envelope 編碼為 NTCP frame。
///
/// # Errors
///
/// Protobuf payload 超過 1 MiB 或長度無法表示為 `u32` 時回傳錯誤。
pub fn encode_frame(envelope: &Envelope) -> Result<Vec<u8>, NetToolError> {
    let payload = envelope.encode_to_vec();
    if payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(frame_error(
            ErrorCode::ControlFrameTooLarge,
            "control payload exceeds 1 MiB",
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        frame_error(
            ErrorCode::ControlFrameTooLarge,
            "control payload length overflow",
        )
    })?;
    let mut frame = Vec::with_capacity(CONTROL_HEADER_BYTES + payload.len());
    frame.extend_from_slice(MAGIC);
    frame.push(FRAMING_VERSION);
    frame.push(0);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// 驗證完整 NTCP frame 並解碼 envelope。
///
/// # Errors
///
/// Header 長度、magic、版本、flags、reserved、payload length 或 Protobuf 無效時回傳穩定錯誤。
pub fn decode_frame(frame: &[u8]) -> Result<Envelope, NetToolError> {
    if frame.len() < CONTROL_HEADER_BYTES {
        return Err(frame_error(
            ErrorCode::ProtocolInvalid,
            "control frame header is truncated",
        ));
    }
    if &frame[..4] != MAGIC {
        return Err(frame_error(
            ErrorCode::ProtocolInvalid,
            "control frame magic is invalid",
        ));
    }
    if frame[4] != FRAMING_VERSION {
        return Err(frame_error(
            ErrorCode::ProtocolIncompatible,
            "control framing version is unsupported",
        ));
    }
    if frame[5] != 0 {
        return Err(frame_error(
            ErrorCode::ProtocolUnsupportedFlag,
            "control frame contains unsupported flags",
        ));
    }
    if frame[6] != 0 || frame[7] != 0 {
        return Err(frame_error(
            ErrorCode::ProtocolInvalid,
            "control frame reserved field must be zero",
        ));
    }
    let payload_length = u32::from_be_bytes(frame[8..12].try_into().map_err(|_| {
        frame_error(
            ErrorCode::ProtocolInvalid,
            "control frame length is invalid",
        )
    })?) as usize;
    if payload_length > MAX_CONTROL_PAYLOAD_BYTES {
        return Err(frame_error(
            ErrorCode::ControlFrameTooLarge,
            "control payload exceeds 1 MiB",
        ));
    }
    if frame.len() != CONTROL_HEADER_BYTES + payload_length {
        return Err(frame_error(
            ErrorCode::ProtocolInvalid,
            "control payload length does not match frame",
        ));
    }
    Envelope::decode(&frame[CONTROL_HEADER_BYTES..]).map_err(|error| {
        frame_error(
            ErrorCode::ProtocolInvalid,
            &format!("invalid control protobuf: {error}"),
        )
    })
}

fn frame_error(code: ErrorCode, message: &str) -> NetToolError {
    NetToolError::new(code, message, false)
}

#[cfg(test)]
mod tests {
    use super::{decode_frame, encode_frame};
    use crate::{Envelope, PROTOCOL_MAJOR, PROTOCOL_MINOR, StartTest, envelope};

    fn envelope() -> Envelope {
        Envelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id: vec![1; 16],
            message: None,
        }
    }

    #[test]
    fn frame_round_trip_uses_network_byte_order() {
        let frame = encode_frame(&envelope()).expect("frame encodes");
        assert_eq!(&frame[..4], b"NTCP");
        assert_eq!(
            u32::from_be_bytes(frame[8..12].try_into().expect("length field")) as usize,
            frame.len() - 12
        );
        assert_eq!(decode_frame(&frame).expect("frame decodes"), envelope());
    }

    #[test]
    fn start_at_survives_control_frame_round_trip() {
        let expected = 1_700_000_000_123_456_789;
        let mut envelope = envelope();
        envelope.message = Some(envelope::ControlMessage::StartTest(StartTest {
            session_id: vec![2; 16],
            operation_id: "start-1".to_owned(),
            start_at_unix_nanoseconds: expected,
        }));
        let decoded = decode_frame(&encode_frame(&envelope).expect("frame")).expect("decode");
        let Some(envelope::ControlMessage::StartTest(start)) = decoded.message else {
            panic!("start message");
        };
        assert_eq!(start.start_at_unix_nanoseconds, expected);
    }

    #[test]
    fn rejects_unknown_flags_and_length_mismatch() {
        let mut flags = encode_frame(&envelope()).expect("frame encodes");
        flags[5] = 1;
        assert!(decode_frame(&flags).is_err());
        let mut truncated = encode_frame(&envelope()).expect("frame encodes");
        truncated.pop();
        assert!(decode_frame(&truncated).is_err());
    }

    #[test]
    fn rejects_all_truncated_headers_without_panicking() {
        for length in 0..12 {
            assert!(decode_frame(&[0_u8; 12][..length]).is_err());
        }
    }
}
