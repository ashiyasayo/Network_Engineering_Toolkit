use super::action_packet::{
    execute_packet_analyze, execute_packet_capture, execute_packet_connections,
    execute_packet_stats,
};
use super::action_persistent::execute;
use super::action_speed::{execute_cancel, execute_speed};
#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) async fn dispatch(envelope: AgentEnvelope, runtime: &AgentRuntime) -> AgentEnvelope {
    let request_id = envelope.request_id;
    let started = std::time::Instant::now();
    let response = match envelope.payload {
        Some(agent_envelope::Payload::Request(request)) => {
            tracing::info!(request_id = %request_id, action = %request.action, operation = %request.operation_id, "agent action started");
            execute_with_runtime(
                &request.action,
                &request.payload_json,
                &request.operation_id,
                request.dry_run,
                runtime,
            )
            .await
        }
        _ => failure("AGENT.INVALID_MESSAGE", "expected action request", false),
    };
    tracing::info!(request_id = %request_id, operation = "agent.dispatch", success = response.success, elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), error_code = %response.error_code, "agent action completed");
    AgentEnvelope {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        request_id,
        payload: Some(agent_envelope::Payload::Response(response)),
    }
}

#[allow(clippy::too_many_lines)]
pub(super) async fn execute_with_runtime(
    action: &str,
    payload: &[u8],
    operation_id: &str,
    dry_run: bool,
    runtime: &AgentRuntime,
) -> ActionResponse {
    if ActionRegistry::find(action).is_none() {
        return failure("ACTION.UNKNOWN", "action is not registered", false);
    }
    if dry_run && !is_helper_action(action) {
        return dry_run_plan(action, payload, operation_id);
    }
    if action == "speed.cancel" {
        return match execute_cancel(payload, runtime).await {
            Ok(value) => ActionResponse {
                success: true,
                data_json: serde_json::to_vec(&value).unwrap_or_default(),
                error_code: String::new(),
                error_message: String::new(),
                retryable: false,
            },
            Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
        };
    }
    if action == "packet.analyze" {
        let result = execute_packet_analyze(payload).await;
        return match result {
            Ok(value) => ActionResponse {
                success: true,
                data_json: serde_json::to_vec(&value).unwrap_or_default(),
                error_code: String::new(),
                error_message: String::new(),
                retryable: false,
            },
            Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
        };
    }
    if matches!(action, "packet.capture.start" | "packet.capture.stop") {
        let result = execute_packet_capture(action, payload, runtime).await;
        return match result {
            Ok(value) => ActionResponse {
                success: true,
                data_json: serde_json::to_vec(&value).unwrap_or_default(),
                error_code: String::new(),
                error_message: String::new(),
                retryable: false,
            },
            Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
        };
    }
    if action == "packet.stats" {
        let result = execute_packet_stats(payload);
        return match result {
            Ok(value) => ActionResponse {
                success: true,
                data_json: serde_json::to_vec(&value).unwrap_or_default(),
                error_code: String::new(),
                error_message: String::new(),
                retryable: false,
            },
            Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
        };
    }
    if action == "packet.connections" {
        let result = execute_packet_connections(payload);
        return match result {
            Ok(value) => ActionResponse {
                success: true,
                data_json: serde_json::to_vec(&value).unwrap_or_default(),
                error_code: String::new(),
                error_message: String::new(),
                retryable: false,
            },
            Err(error) => failure(error.code.as_str(), &error.message, error.retryable),
        };
    }
    if matches!(
        action,
        "profile.create" | "profile.edit" | "profile.delete" | "profile.import"
    ) {
        let result = {
            let mut storage = runtime.storage.lock().await;
            super::action_profile::execute_mutation(action, payload, &mut storage)
        };
        return result_response(result);
    }
    if matches!(action, "node.pair" | "node.revoke") {
        let result = {
            let mut storage = runtime.storage.lock().await;
            super::action_node::execute_mutation(action, payload, &mut storage)
        };
        return result_response(result);
    }
    if matches!(
        action,
        "profile.apply" | "profile.confirm" | "profile.rollback"
    ) {
        return result_response(
            super::action_profile::execute_privileged(
                action,
                payload,
                operation_id,
                dry_run,
                runtime,
            )
            .await,
        );
    }
    if matches!(action, "ip.set" | "ip.dhcp" | "dns.set") {
        return result_response(
            super::action_helper::execute(action, payload, operation_id, dry_run).await,
        );
    }
    if matches!(
        action,
        "hosts.replace"
            | "hosts.add"
            | "hosts.remove"
            | "hosts.enable"
            | "hosts.disable"
            | "hosts.backup"
            | "hosts.restore"
            | "hosts.read"
    ) {
        return result_response(
            super::action_hosts::execute(action, payload, operation_id, dry_run).await,
        );
    }
    if matches!(action, "profile.list" | "profile.show" | "profile.export") {
        let storage = runtime.storage.lock().await;
        return result_response(super::action_profile::execute_read(
            action, payload, &storage,
        ));
    }
    if matches!(action, "node.list" | "node.status") {
        let storage = runtime.storage.lock().await;
        return result_response(super::action_node::execute_read(action, &storage));
    }
    if matches!(
        action,
        "dataplane.probe"
            | "perf.topology"
            | "perf.backend"
            | "perf.profile.list"
            | "perf.benchmark"
    ) {
        return result_response(super::action_perf::execute(action, payload));
    }
    if action == "speed.history" {
        let storage = runtime.storage.lock().await;
        return result_response(super::action_speed::execute_history(payload, &storage));
    }
    if action != "speed.run" {
        let storage = runtime.storage.lock().await;
        return execute(action, payload, &storage);
    }
    result_response(execute_speed(payload, runtime).await)
}

pub(super) fn result_response(result: Result<serde_json::Value, NetToolError>) -> ActionResponse {
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
