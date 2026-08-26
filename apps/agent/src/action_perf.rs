#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkPayload {
    profile: String,
}

fn parse_benchmark_payload(payload: &[u8]) -> Result<BenchmarkPayload, NetToolError> {
    serde_json::from_slice(payload).map_err(|error| {
        NetToolError::new(
            ErrorCode::InvalidArgument,
            format!("invalid benchmark payload: {error}"),
            false,
        )
    })
}

pub(super) fn validate_benchmark_payload(payload: &[u8]) -> Result<(), NetToolError> {
    let request = parse_benchmark_payload(payload)?;
    let profile = BenchmarkProfileRegistry::get(&request.profile).ok_or_else(|| {
        NetToolError::new(
            ErrorCode::InvalidArgument,
            "benchmark profile does not exist",
            false,
        )
    })?;
    profile.plan.validate()
}

pub(super) fn execute(action: &str, payload: &[u8]) -> Result<serde_json::Value, NetToolError> {
    match action {
        "dataplane.probe" => probe_environment().map(|report| {
            json!({
                "schema_version":report.schema_version,
                "platform":report.platform.as_str(),
                "logical_cpus":report.logical_cpus,
                "numa_nodes":report.numa_nodes,
                "huge_pages_total":report.huge_pages_total,
                "huge_pages_free":report.huge_pages_free,
                "huge_page_size_kib":report.huge_page_size_kib,
                "nics":report.nics.iter().map(|nic| json!({
                    "name":nic.name,
                    "pci_address":nic.pci_address,
                    "bus_type":nic.bus_type,
                    "driver":nic.driver,
                    "link_speed_mbps":nic.link_speed_mbps,
                    "rx_queues":nic.rx_queues,
                    "tx_queues":nic.tx_queues,
                    "numa_node":nic.numa_node
                })).collect::<Vec<_>>(),
                "dpdk_capable":report.dpdk_capable,
                "af_xdp_capable":report.af_xdp_capable,
                "af_xdp_zero_copy_capable":report.af_xdp_zero_copy_capable,
                "rio_platform_capable":cfg!(target_os = "windows"),
                "rio_implementation_available":nettool_backend_rio::is_backend_built(),
                "warnings":report.warnings
            })
        }),
        "perf.topology" => probe_environment().map(|report| {
            json!({
                "schema_version":"1.0",
                "platform":report.platform.as_str(),
                "cpu":{"logical_count":report.logical_cpus},
                "numa":{"node_count":report.numa_nodes},
                "huge_pages":{"total":report.huge_pages_total,"free":report.huge_pages_free,"size_kib":report.huge_page_size_kib},
                "nics":report.nics.iter().map(|nic| json!({
                    "name":nic.name,
                    "pci_address":nic.pci_address,
                    "bus_type":nic.bus_type,
                    "link_speed_mbps":nic.link_speed_mbps,
                    "numa_node":nic.numa_node,
                    "rx_queues":nic.rx_queues,
                    "tx_queues":nic.tx_queues,
                    "driver":nic.driver
                })).collect::<Vec<_>>(),
                "warnings":report.warnings
            })
        }),
        "perf.backend" => probe_environment().map(|report| {
            let dpdk_built = nettool_backend_dpdk::is_backend_built();
            let rio_built = nettool_backend_rio::is_backend_built();
            let rio_preflight = nettool_backend_rio::evaluate_rio_preflight(
                cfg!(target_os = "windows"),
                rio_built,
            );
            json!({
                "schema_version":"1.0",
                "backends":[
                    {"id":"pcap","available":true,"mode":"offline","implementation_available":true},
                    {"id":"af_xdp","available":report.af_xdp_capable && nettool_backend_af_xdp::is_backend_built(),"mode":"accelerated","platform_capable":report.af_xdp_capable,"implementation_available":nettool_backend_af_xdp::is_backend_built()},
                    {"id":"dpdk","available":dpdk_built && report.dpdk_capable,"mode":"accelerated","runtime_available":report.dpdk_capable,"implementation_available":dpdk_built},
                    {"id":"rio","available":rio_preflight.can_run,"mode":"accelerated","platform_capable":cfg!(target_os = "windows"),"implementation_available":rio_built,"preflight_can_run":rio_preflight.can_run,"preflight_checks":rio_preflight.checks.iter().map(|check| json!({"id":check.id,"severity":format!("{:?}",check.severity),"message":check.message})).collect::<Vec<_>>()}
                ],
                "warnings":report.warnings
            })
        }),
        "perf.profile.list" => Ok(json!({
            "schema_version":"1.0",
            "profiles":BenchmarkProfileRegistry::ids().into_iter().filter_map(|id| {
                BenchmarkProfileRegistry::get(id).map(|profile| json!({
                    "id":id,
                    "plan":profile.plan,
                    "certification_policy_configured":profile.certification_policy.is_some()
                }))
            }).collect::<Vec<_>>()
        })),
        "perf.benchmark" => parse_benchmark_payload(payload).and_then(|request| {
            let profile = BenchmarkProfileRegistry::get(&request.profile).ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "benchmark profile does not exist",
                    false,
                )
            })?;
            profile.plan.validate()?;
            Err(NetToolError::new(
                ErrorCode::BackendNotBuilt,
                "benchmark plan is valid, but no accelerated hardware phase executor is linked",
                false,
            ))
        }),
        _ => Err(NetToolError::new(
            ErrorCode::ActionUnsupported,
            "performance action is not attached",
            false,
        )),
    }
}
