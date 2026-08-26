#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InterfaceTargetPayload {
    pub(super) name_or_id: String,
}

pub(super) fn parse_interface_target(
    payload: &[u8],
) -> Result<InterfaceTargetPayload, NetToolError> {
    serde_json::from_slice(payload).map_err(|error| {
        NetToolError::new(
            ErrorCode::InvalidArgument,
            format!("invalid interface target payload: {error}"),
            false,
        )
    })
}

pub(super) fn execute(action: &str, payload: &[u8], storage: &Storage) -> ActionResponse {
    if ActionRegistry::find(action).is_none() {
        return failure("ACTION.UNKNOWN", "action is not registered", false);
    }
    let result = match action {
        "system.health" => storage
            .schema_version()
            .map(|version| json!({"status":"healthy","schema_version":version})),
        "interface.list" | "interface.refresh" => probe_environment().map(|report| {
            json!({
                "schema_version": report.schema_version,
                "interfaces": report.nics.iter().map(|nic| json!({
                    "name": nic.name,
                    "pci_address": nic.pci_address,
                    "driver": nic.driver,
                    "link_speed_mbps": nic.link_speed_mbps,
                    "rx_queues": nic.rx_queues,
                    "tx_queues": nic.tx_queues,
                    "numa_node": nic.numa_node
                })).collect::<Vec<_>>()
            })
        }),
        "interface.show" => parse_interface_target(payload).and_then(|request| {
            probe_environment().and_then(|report| {
                let nic = report.nics.iter().find(|nic| {
                    nic.name == request.name_or_id
                        || nic.pci_address.as_deref() == Some(request.name_or_id.as_str())
                });
                nic.map_or_else(
                    || {
                        Err(NetToolError::new(
                            ErrorCode::InvalidArgument,
                            "interface does not exist",
                            false,
                        ))
                    },
                    |nic| {
                        Ok(json!({
                            "schema_version": report.schema_version,
                            "interface": {
                                "name": nic.name,
                                "pci_address": nic.pci_address,
                                "driver": nic.driver,
                                "link_speed_mbps": nic.link_speed_mbps,
                                "rx_queues": nic.rx_queues,
                                "tx_queues": nic.tx_queues,
                                "numa_node": nic.numa_node
                            }
                        }))
                    },
                )
            })
        }),
        _ => Err(NetToolError::new(
            ErrorCode::ActionUnsupported,
            "persistent action is not attached",
            false,
        )),
    };
    match result {
        Ok(value) => ActionResponse {
            success: true,
            data_json: serde_json::to_vec(&value).unwrap_or_default(),
            error_code: String::new(),
            error_message: String::new(),
            retryable: false,
        },
        Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
    }
}
