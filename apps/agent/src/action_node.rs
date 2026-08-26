#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodePairPayload {
    pub(super) node_id: String,
    pub(super) name: String,
    pub(super) control_address: String,
    pub(super) server_name: String,
    pub(super) fingerprint: String,
    pub(super) certificate_der: Vec<u8>,
    pub(super) out_of_band_fingerprint_confirmed: bool,
    pub(super) identity_change_confirmed: bool,
}

pub(super) fn execute_read(
    action: &str,
    storage: &Storage,
) -> Result<serde_json::Value, NetToolError> {
    match action {
        "node.list" | "node.status" => storage.list_trusted_nodes().map(|nodes| {
            json!({
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
            })
        }),
        _ => Err(NetToolError::new(
            ErrorCode::ActionUnsupported,
            "node read action is not attached",
            false,
        )),
    }
}

pub(super) fn execute_mutation(
    action: &str,
    payload: &[u8],
    storage: &mut Storage,
) -> Result<serde_json::Value, NetToolError> {
    match action {
        "node.revoke" => {
            let request = super::action_profile::parse_profile_target(payload)?;
            let node = storage.revoke_trusted_node(&request.id_or_name)?;
            Ok(json!({
                "revoked": true,
                "node_id": node.id,
                "name": node.name,
                "fingerprint": node.fingerprint,
            }))
        }
        "node.pair" => {
            let request: NodePairPayload = serde_json::from_slice(payload).map_err(|error| {
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
        _ => Err(NetToolError::new(
            ErrorCode::ActionUnsupported,
            "node mutation action is not attached",
            false,
        )),
    }
}
