#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileApplyPayload {
    id_or_name: String,
    interface_id: String,
    #[serde(default)]
    confirm_timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperOperationPayload {
    operation_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileCreatePayload {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) configuration: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileEditPayload {
    pub(super) id_or_name: String,
    pub(super) name: String,
    pub(super) configuration: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileImportPayload {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) configuration: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileTargetPayload {
    pub(super) id_or_name: String,
}

pub(super) fn parse_profile_target(payload: &[u8]) -> Result<ProfileTargetPayload, NetToolError> {
    serde_json::from_slice(payload).map_err(|error| {
        NetToolError::new(
            ErrorCode::InvalidArgument,
            format!("invalid profile target payload: {error}"),
            false,
        )
    })
}

pub(super) fn execute_read(
    action: &str,
    payload: &[u8],
    storage: &Storage,
) -> Result<serde_json::Value, NetToolError> {
    match action {
        "profile.list" => storage.list_profiles().and_then(|profiles| {
            serde_json::to_value(profiles).map_err(|error| storage_error(error.to_string()))
        }),
        "profile.show" => parse_profile_target(payload).and_then(|request| {
            storage.get_profile(&request.id_or_name)?.map_or_else(
                || {
                    Err(NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "profile does not exist",
                        false,
                    ))
                },
                |value| {
                    serde_json::to_value(value).map_err(|error| storage_error(error.to_string()))
                },
            )
        }),
        "profile.export" => parse_profile_target(payload).and_then(|request| {
            storage.get_profile(&request.id_or_name)?.map_or_else(
                || {
                    Err(NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "profile does not exist",
                        false,
                    ))
                },
                |document| {
                    Ok(json!({
                        "format": "nettool.profile.v1",
                        "id": document.summary.id,
                        "name": document.summary.name,
                        "revision": document.summary.active_revision,
                        "configuration": document.configuration,
                    }))
                },
            )
        }),
        _ => Err(NetToolError::new(
            ErrorCode::ActionUnsupported,
            "profile read action is not attached",
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
        "profile.create" => {
            let request: ProfileCreatePayload =
                serde_json::from_slice(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid profile create payload: {error}"),
                        false,
                    )
                })?;
            let summary = storage.create_profile(
                &request.id,
                &request.name,
                &request.configuration,
                &utc_timestamp(),
            )?;
            serde_json::to_value(summary).map_err(|error| storage_error(error.to_string()))
        }
        "profile.edit" => {
            let request: ProfileEditPayload = serde_json::from_slice(payload).map_err(|error| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid profile edit payload: {error}"),
                    false,
                )
            })?;
            let summary = storage.update_profile(
                &request.id_or_name,
                &request.name,
                &request.configuration,
                &utc_timestamp(),
            )?;
            serde_json::to_value(summary).map_err(|error| storage_error(error.to_string()))
        }
        "profile.import" => {
            let request: ProfileImportPayload =
                serde_json::from_slice(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid profile import payload: {error}"),
                        false,
                    )
                })?;
            let summary = storage.create_profile(
                &request.id,
                &request.name,
                &request.configuration,
                &utc_timestamp(),
            )?;
            serde_json::to_value(summary).map_err(|error| storage_error(error.to_string()))
        }
        "profile.delete" => {
            let request = parse_profile_target(payload)?;
            let summary = storage.delete_profile(&request.id_or_name)?;
            serde_json::to_value(summary).map_err(|error| storage_error(error.to_string()))
        }
        _ => Err(NetToolError::new(
            ErrorCode::ActionUnsupported,
            "profile mutation action is not attached",
            false,
        )),
    }
}

pub(super) async fn execute_privileged(
    action: &str,
    payload: &[u8],
    operation_id: &str,
    dry_run: bool,
    runtime: &AgentRuntime,
) -> Result<serde_json::Value, NetToolError> {
    let (operation, helper_operation_id) = match action {
        "profile.apply" => {
            let request: ProfileApplyPayload =
                serde_json::from_slice(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid profile apply payload: {error}"),
                        false,
                    )
                })?;
            let document = runtime
                .storage
                .lock()
                .await
                .get_profile(&request.id_or_name)?
                .ok_or_else(|| {
                    NetToolError::new(ErrorCode::InvalidArgument, "profile does not exist", false)
                })?;
            let desired_state = network_desired_state_from_profile(document.configuration)?;
            let helper_operation_id = if operation_id.trim().is_empty() {
                format!(
                    "profile-apply-{}-{}",
                    document.summary.id, request.interface_id
                )
            } else {
                operation_id.to_owned()
            };
            (
                PrivilegedOperation::NetworkApply {
                    interface_id: request.interface_id,
                    desired_state,
                    confirm_timeout_seconds: request.confirm_timeout_seconds.unwrap_or(60),
                },
                helper_operation_id,
            )
        }
        "profile.confirm" => {
            let request: HelperOperationPayload =
                serde_json::from_slice(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid profile confirm payload: {error}"),
                        false,
                    )
                })?;
            (
                PrivilegedOperation::SafeApplyConfirm {
                    operation_id: request.operation_id.clone(),
                },
                request.operation_id,
            )
        }
        "profile.rollback" => {
            let request: HelperOperationPayload =
                serde_json::from_slice(payload).map_err(|error| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid profile rollback payload: {error}"),
                        false,
                    )
                })?;
            (
                PrivilegedOperation::SafeApplyRollback {
                    operation_id: request.operation_id.clone(),
                },
                request.operation_id,
            )
        }
        _ => {
            return Err(NetToolError::new(
                ErrorCode::ActionUnsupported,
                "profile privileged action is not attached",
                false,
            ));
        }
    };
    super::action_helper::helper_call(&helper_operation_id, operation, dry_run).await
}

fn network_desired_state_from_profile(
    configuration: serde_json::Value,
) -> Result<NetworkDesiredState, NetToolError> {
    if let Ok(desired_state) = serde_json::from_value::<NetworkDesiredState>(configuration.clone())
    {
        return Ok(desired_state);
    }
    let profile: nettool_domain::NetworkProfile =
        serde_json::from_value(configuration).map_err(|error| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("profile configuration is not a valid network profile: {error}"),
                false,
            )
        })?;
    Ok(NetworkDesiredState {
        ipv4: profile.ipv4,
        ipv6: profile.ipv6,
        dns: profile.dns,
        routes: profile.routes,
        mtu: profile.mtu,
    })
}
