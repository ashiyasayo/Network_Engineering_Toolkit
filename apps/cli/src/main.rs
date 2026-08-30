//! Agent Action API 的穩定 CLI adapter。

#![forbid(unsafe_code)]

use nettool_agent_client::{default_socket_path, request};
use nettool_agent_protocol::{
    ActionRequest, AgentEnvelope, PROTOCOL_MAJOR, PROTOCOL_MINOR, agent_envelope,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[tokio::main]
async fn main() -> ExitCode {
    match run(std::env::args().skip(1)).await {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({"schema_version":"1.0","success":false,"error":error})
            );
            ExitCode::from(2)
        }
    }
}

async fn run(args: impl Iterator<Item = String>) -> Result<String, Value> {
    let (dry_run, filtered_args) = split_dry_run(args)?;
    let (action, output_json, action_payload) = parse_args(filtered_args.into_iter())?;
    let request_id = request_id();
    let descriptor = nettool_action::ActionRegistry::find(action).ok_or_else(
        || json!({"code":"ACTION.UNKNOWN","message":"action is not registered","retryable":false}),
    )?;
    let envelope = AgentEnvelope {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        request_id: request_id.clone(),
        payload: Some(agent_envelope::Payload::Request(ActionRequest {
            action: action.to_owned(),
            payload_json: serde_json::to_vec(&action_payload).map_err(
                |error| json!({"code":"CLI.INVALID_JSON","message":error.to_string(),"retryable":false}),
            )?,
            operation_id: if descriptor.idempotent {
                String::new()
            } else {
                request_id.clone()
            },
            dry_run,
        })),
    };
    let response = request(&default_socket_path(), &envelope).await.map_err(|error| json!({"code":error.code.as_str(),"message":error.message,"retryable":error.retryable}))?;
    if response.request_id != request_id {
        return Err(
            json!({"code":"AGENT.REQUEST_MISMATCH","message":"agent response request ID does not match","retryable":false}),
        );
    }
    let Some(agent_envelope::Payload::Response(response)) = response.payload else {
        return Err(
            json!({"code":"AGENT.INVALID_MESSAGE","message":"agent did not return an action response","retryable":false}),
        );
    };
    if !response.success {
        return Err(
            json!({"code":response.error_code,"message":response.error_message,"retryable":response.retryable}),
        );
    }
    let value: Value = serde_json::from_slice(&response.data_json).map_err(
        |error| json!({"code":"AGENT.INVALID_JSON","message":error.to_string(),"retryable":false}),
    )?;
    if action == "speed.history" && action_payload["format"] == "csv" {
        return Ok(speed_history_csv(&value));
    }
    if output_json {
        Ok(
            json!({"schema_version":"1.0","success":true,"request_id":request_id,"data":value})
                .to_string(),
        )
    } else {
        Ok(human_output(action, &value))
    }
}

fn split_dry_run(args: impl IntoIterator<Item = String>) -> Result<(bool, Vec<String>), Value> {
    let mut dry_run = false;
    let mut filtered_args = Vec::new();
    for argument in args {
        if argument == "--dry-run" {
            if dry_run {
                return Err(cli_error("duplicate --dry-run"));
            }
            dry_run = true;
        } else {
            filtered_args.push(argument);
        }
    }
    Ok((dry_run, filtered_args))
}

#[allow(clippy::too_many_lines)]
fn parse_args(args: impl Iterator<Item = String>) -> Result<(&'static str, bool, Value), Value> {
    let mut values: Vec<_> = args.collect();
    let output_json = if values.ends_with(&["--output".to_owned(), "json".to_owned()]) {
        values.truncate(values.len() - 2);
        true
    } else {
        false
    };
    if values
        .get(..2)
        .is_some_and(|prefix| prefix == ["speed", "run"])
    {
        return parse_speed_run(&values[2..]).map(|payload| ("speed.run", output_json, payload));
    }
    if values
        .get(..2)
        .is_some_and(|prefix| prefix == ["speed", "history"])
    {
        return parse_speed_history(&values[2..])
            .map(|payload| ("speed.history", output_json, payload));
    }
    if values
        .get(..2)
        .is_some_and(|prefix| prefix == ["profile", "apply"])
    {
        return parse_profile_apply(&values[2..])
            .map(|payload| ("profile.apply", output_json, payload));
    }
    if values
        .get(..2)
        .is_some_and(|prefix| prefix == ["ip", "set"])
    {
        return parse_ip_set(&values[2..]).map(|payload| ("ip.set", output_json, payload));
    }
    if values
        .get(..2)
        .is_some_and(|prefix| prefix == ["ip", "dhcp"])
    {
        return parse_ip_dhcp(&values[2..]).map(|payload| ("ip.dhcp", output_json, payload));
    }
    if values
        .get(..2)
        .is_some_and(|prefix| prefix == ["dns", "set"])
    {
        return parse_dns_set(&values[2..]).map(|payload| ("dns.set", output_json, payload));
    }
    if values
        .get(..2)
        .is_some_and(|prefix| prefix == ["packet", "analyze"])
    {
        return parse_packet_analyze(&values[2..])
            .map(|payload| ("packet.analyze", output_json, payload));
    }
    if values
        .get(..2)
        .is_some_and(|prefix| prefix == ["packet", "stats"])
    {
        return parse_packet_stats(&values[2..])
            .map(|payload| ("packet.stats", output_json, payload));
    }
    if values
        .get(..2)
        .is_some_and(|prefix| prefix == ["packet", "connections"])
    {
        return parse_packet_connections(&values[2..])
            .map(|payload| ("packet.connections", output_json, payload));
    }
    if values
        .get(..3)
        .is_some_and(|prefix| prefix == ["packet", "capture", "start"])
    {
        return parse_packet_capture_start(&values[3..])
            .map(|payload| ("packet.capture.start", output_json, payload));
    }
    if values
        .get(..2)
        .is_some_and(|prefix| prefix == ["node", "pair"])
    {
        return parse_node_pair(&values[2..]).map(|payload| ("node.pair", output_json, payload));
    }
    let (action, payload) = match values
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["interface", "list" | "refresh"] => {
            let action = if values[1] == "list" {
                "interface.list"
            } else {
                "interface.refresh"
            };
            (action, json!({}))
        }
        ["interface", "show", name_or_id] if !name_or_id.trim().is_empty() => {
            ("interface.show", json!({"name_or_id": name_or_id}))
        }
        ["health"] => ("system.health", json!({})),
        ["profile", "list"] => ("profile.list", json!({})),
        ["profile", "show", id_or_name] if !id_or_name.trim().is_empty() => {
            ("profile.show", json!({"id_or_name": id_or_name}))
        }
        ["profile", "create", id, name, configuration]
            if !id.trim().is_empty() && !name.trim().is_empty() =>
        {
            let configuration: Value = serde_json::from_str(configuration).map_err(|error| {
                cli_error(&format!("profile configuration is invalid: {error}"))
            })?;
            (
                "profile.create",
                json!({"id": id, "name": name, "configuration": configuration}),
            )
        }
        ["profile", "delete", id_or_name] if !id_or_name.trim().is_empty() => {
            ("profile.delete", json!({"id_or_name": id_or_name}))
        }
        ["profile", "edit", id_or_name, name, configuration]
            if !id_or_name.trim().is_empty() && !name.trim().is_empty() =>
        {
            let configuration: Value = serde_json::from_str(configuration).map_err(|error| {
                cli_error(&format!("profile configuration is invalid: {error}"))
            })?;
            (
                "profile.edit",
                json!({"id_or_name": id_or_name, "name": name, "configuration": configuration}),
            )
        }
        ["profile", "export", id_or_name] if !id_or_name.trim().is_empty() => {
            ("profile.export", json!({"id_or_name": id_or_name}))
        }
        ["profile", "import", path] if !path.trim().is_empty() => {
            let document: Value =
                serde_json::from_str(&fs::read_to_string(path).map_err(|error| {
                    cli_error(&format!("profile file cannot be read: {error}"))
                })?)
                .map_err(|error| cli_error(&format!("profile file is invalid JSON: {error}")))?;
            let id = document
                .get("id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| cli_error("profile file requires a non-empty id"))?;
            let name = document
                .get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| cli_error("profile file requires a non-empty name"))?;
            let configuration = document
                .get("configuration")
                .cloned()
                .ok_or_else(|| cli_error("profile file requires configuration"))?;
            (
                "profile.import",
                json!({"id": id, "name": name, "configuration": configuration}),
            )
        }
        ["profile", "confirm", operation_id] if !operation_id.trim().is_empty() => {
            ("profile.confirm", json!({"operation_id": operation_id}))
        }
        ["profile", "rollback", operation_id] if !operation_id.trim().is_empty() => {
            ("profile.rollback", json!({"operation_id": operation_id}))
        }
        ["hosts", "replace", profile_id, entries_json] if !profile_id.trim().is_empty() => {
            let entries: Value = serde_json::from_str(entries_json)
                .map_err(|error| cli_error(&format!("hosts entries are invalid: {error}")))?;
            (
                "hosts.replace",
                json!({"profile_id": profile_id, "entries": entries}),
            )
        }
        ["hosts", "list"] => ("hosts.read", json!({})),
        ["hosts", "add", profile_id, address, hostname]
            if !profile_id.trim().is_empty()
                && !address.trim().is_empty()
                && !hostname.trim().is_empty() =>
        {
            (
                "hosts.add",
                json!({"profile_id": profile_id, "address": address, "hostname": hostname}),
            )
        }
        ["hosts", "add", profile_id, address, hostname, comment]
            if !profile_id.trim().is_empty()
                && !address.trim().is_empty()
                && !hostname.trim().is_empty() =>
        {
            (
                "hosts.add",
                json!({"profile_id": profile_id, "address": address, "hostname": hostname, "comment": comment}),
            )
        }
        ["hosts", "remove", profile_id, hostname]
            if !profile_id.trim().is_empty() && !hostname.trim().is_empty() =>
        {
            (
                "hosts.remove",
                json!({"profile_id": profile_id, "hostname": hostname}),
            )
        }
        ["hosts", "enable" | "disable", profile_id, hostname]
            if !profile_id.trim().is_empty() && !hostname.trim().is_empty() =>
        {
            let action = if values[1] == "enable" {
                "hosts.enable"
            } else {
                "hosts.disable"
            };
            (
                action,
                json!({"profile_id": profile_id, "hostname": hostname}),
            )
        }
        ["hosts", "backup"] => ("hosts.backup", json!({})),
        ["hosts", "restore"] => ("hosts.restore", json!({})),
        ["node", "list"] => ("node.list", json!({})),
        ["node", "status"] => ("node.status", json!({})),
        ["node", "revoke", id_or_name] if !id_or_name.trim().is_empty() => {
            ("node.revoke", json!({"id_or_name": id_or_name}))
        }
        ["dataplane", "probe"] => ("dataplane.probe", json!({})),
        ["speed", "cancel", session_id] if !session_id.trim().is_empty() => {
            ("speed.cancel", json!({"session_id": session_id}))
        }
        ["packet", "capture", "stop", session_id] if !session_id.trim().is_empty() => {
            ("packet.capture.stop", json!({"session_id": session_id}))
        }
        ["perf", "topology"] => ("perf.topology", json!({})),
        ["perf", "backend"] => ("perf.backend", json!({})),
        ["perf", "profile", "list"] => ("perf.profile.list", json!({})),
        ["perf", "benchmark", "--profile", profile] if !profile.trim().is_empty() => {
            ("perf.benchmark", json!({"profile":profile}))
        }
        _ => {
            return Err(
                json!({"code":"CLI.INVALID_ARGUMENT","message":"usage: nettool [--dry-run] <interface list|interface show <name-or-id>|interface refresh|health|profile list|profile show <id-or-name>|profile create <id> <name> <json>|profile edit <id-or-name> <name> <json>|profile export <id-or-name>|profile import <file>|profile apply <id-or-name> --interface <id>|profile confirm <operation-id>|profile rollback <operation-id>|profile delete <id-or-name>|ip set --interface <id> --address <ip> --prefix <n>|ip dhcp --interface <id>|dns set --interface <id> --server <ip>|hosts list|hosts replace <profile-id> <json>|hosts add <profile-id> <address> <hostname> [comment]|hosts remove <profile-id> <hostname>|hosts enable <profile-id> <hostname>|hosts disable <profile-id> <hostname>|hosts backup|hosts restore|node pair --id <id> --name <name> --address <ip:port> --server-name <name> --fingerprint <fp> --certificate <file> --confirm-fingerprint [--confirm-identity-change]|node list|node status|node revoke <id-or-name>|packet capture start --interface <id> --output <directory> --bursts <n>|packet capture stop <session-id>|packet analyze --input <capture>|packet stats [--interface <id>]|packet connections [--protocol tcp|udp]|dataplane probe|speed run <node> [options]|speed history [--limit <n>]|speed cancel <session-id>|perf topology|perf backend|perf profile list|perf benchmark --profile <id>> [--output json]","retryable":false}),
            );
        }
    };
    Ok((action, output_json, payload))
}

fn parse_profile_apply(arguments: &[String]) -> Result<Value, Value> {
    let profile = arguments
        .first()
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| cli_error("profile apply requires an ID or name"))?;
    let mut interface_id = None;
    let mut timeout_seconds = None;
    let mut index = 1;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| cli_error(&format!("missing value for {flag}")))?;
        match flag {
            "--interface" if !value.trim().is_empty() => interface_id = Some(value.clone()),
            "--confirm-timeout" | "--timeout" => {
                timeout_seconds = Some(parse_nonzero::<u64>(value, "confirm-timeout")?);
            }
            _ => {
                return Err(cli_error(&format!(
                    "unknown or invalid profile apply option: {flag}"
                )));
            }
        }
        index += 2;
    }
    let interface_id =
        interface_id.ok_or_else(|| cli_error("profile apply requires --interface"))?;
    Ok(json!({
        "id_or_name": profile,
        "interface_id": interface_id,
        "confirm_timeout_seconds": timeout_seconds,
    }))
}

fn parse_ip_set(arguments: &[String]) -> Result<Value, Value> {
    let mut interface_id = None;
    let mut address = None;
    let mut prefix = None;
    let mut gateway = None;
    let mut timeout_seconds = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| cli_error(&format!("missing value for {flag}")))?;
        match flag {
            "--interface" => interface_id = Some(value.clone()),
            "--address" => address = Some(value.clone()),
            "--prefix" => prefix = Some(parse_nonzero_or_zero::<u8>(value, "prefix")?),
            "--gateway" => gateway = Some(value.clone()),
            "--timeout" => timeout_seconds = Some(parse_nonzero::<u64>(value, "timeout")?),
            _ => {
                return Err(cli_error(&format!(
                    "unknown or invalid ip set option: {flag}"
                )));
            }
        }
        index += 2;
    }
    Ok(json!({
        "interface_id": interface_id.ok_or_else(|| cli_error("ip set requires --interface"))?,
        "address": address.ok_or_else(|| cli_error("ip set requires --address"))?,
        "prefix_length": prefix.ok_or_else(|| cli_error("ip set requires --prefix"))?,
        "gateway": gateway,
        "confirm_timeout_seconds": timeout_seconds,
    }))
}

fn parse_ip_dhcp(arguments: &[String]) -> Result<Value, Value> {
    parse_interface_timeout(arguments, "ip dhcp")
}

fn parse_dns_set(arguments: &[String]) -> Result<Value, Value> {
    let mut interface_id = None;
    let mut servers = Vec::new();
    let mut timeout_seconds = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| cli_error(&format!("missing value for {flag}")))?;
        match flag {
            "--interface" => interface_id = Some(value.clone()),
            "--server" => servers.push(value.clone()),
            "--timeout" => timeout_seconds = Some(parse_nonzero::<u64>(value, "timeout")?),
            _ => {
                return Err(cli_error(&format!(
                    "unknown or invalid dns set option: {flag}"
                )));
            }
        }
        index += 2;
    }
    if servers.is_empty() {
        return Err(cli_error("dns set requires at least one --server"));
    }
    Ok(json!({
        "interface_id": interface_id.ok_or_else(|| cli_error("dns set requires --interface"))?,
        "servers": servers,
        "confirm_timeout_seconds": timeout_seconds,
    }))
}

fn parse_interface_timeout(arguments: &[String], command: &str) -> Result<Value, Value> {
    let mut interface_id = None;
    let mut timeout_seconds = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| cli_error(&format!("missing value for {flag}")))?;
        match flag {
            "--interface" => interface_id = Some(value.clone()),
            "--timeout" => timeout_seconds = Some(parse_nonzero::<u64>(value, "timeout")?),
            _ => {
                return Err(cli_error(&format!(
                    "unknown or invalid {command} option: {flag}"
                )));
            }
        }
        index += 2;
    }
    Ok(json!({
        "interface_id": interface_id.ok_or_else(|| cli_error(&format!("{command} requires --interface")))?,
        "confirm_timeout_seconds": timeout_seconds,
    }))
}

fn parse_speed_history(arguments: &[String]) -> Result<Value, Value> {
    let mut limit = 100_u32;
    let mut limit_seen = false;
    let mut format = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--limit" => {
                if index + 1 >= arguments.len() {
                    return Err(cli_error("speed history requires a value after --limit"));
                }
                if limit_seen {
                    return Err(cli_error("duplicate --limit"));
                }
                limit_seen = true;
                limit = parse_nonzero::<u32>(&arguments[index + 1], "history limit")?;
                if limit > 10_000 {
                    return Err(cli_error("history limit must be between 1 and 10000"));
                }
                index += 2;
            }
            "--format" => {
                if index + 1 >= arguments.len() {
                    return Err(cli_error("speed history requires a value after --format"));
                }
                if format.is_some() {
                    return Err(cli_error("duplicate --format"));
                }
                if arguments[index + 1] != "csv" {
                    return Err(cli_error("speed history format must be csv"));
                }
                format = Some("csv");
                index += 2;
            }
            _ => {
                return Err(cli_error(
                    "speed history accepts --limit <n> and --format csv",
                ));
            }
        }
    }
    let mut payload = json!({"limit": limit});
    if let Some(format) = format {
        payload["format"] = json!(format);
    }
    Ok(payload)
}

fn speed_history_csv(value: &Value) -> String {
    let mut output = String::from(
        "session_id,remote_node,protocol,backend,direction,started_at,completed_at,state\n",
    );
    if let Some(rows) = value.as_array() {
        for row in rows {
            let fields = [
                row["session_id"].as_str().unwrap_or_default(),
                row["remote_node"].as_str().unwrap_or_default(),
                row["protocol"].as_str().unwrap_or_default(),
                row["backend"].as_str().unwrap_or_default(),
                row["direction"].as_str().unwrap_or_default(),
                row["started_at"].as_str().unwrap_or_default(),
                row["completed_at"].as_str().unwrap_or_default(),
                row["state"].as_str().unwrap_or_default(),
            ];
            output.push_str(
                &fields
                    .iter()
                    .map(|field| csv_escape(field))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            output.push('\n');
        }
    }
    output
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn parse_packet_analyze(arguments: &[String]) -> Result<Value, Value> {
    let mut input = None;
    let mut sample_one_in = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| cli_error(&format!("missing value for {flag}")))?;
        match flag {
            "--input" if input.is_none() => input = Some(value.clone()),
            "--sample-one-in" if sample_one_in.is_none() => {
                sample_one_in = Some(parse_nonzero::<u32>(value, "sample ratio")?);
            }
            _ => {
                return Err(cli_error(&format!(
                    "unknown or duplicate packet analyze option: {flag}"
                )));
            }
        }
        index += 2;
    }
    Ok(json!({
        "input": input.ok_or_else(|| cli_error("packet analyze requires --input"))?,
        "sample_one_in": sample_one_in,
    }))
}

fn parse_packet_stats(arguments: &[String]) -> Result<Value, Value> {
    match arguments {
        [] => Ok(json!({})),
        [flag, interface_id] if flag == "--interface" && !interface_id.trim().is_empty() => {
            Ok(json!({"interface_id": interface_id}))
        }
        _ => Err(cli_error("packet stats accepts only --interface <id>")),
    }
}

fn parse_packet_connections(arguments: &[String]) -> Result<Value, Value> {
    match arguments {
        [] => Ok(json!({"protocol": null})),
        [flag, protocol] if flag == "--protocol" && matches!(protocol.as_str(), "tcp" | "udp") => {
            Ok(json!({"protocol": protocol}))
        }
        _ => Err(cli_error(
            "packet connections accepts only --protocol tcp|udp",
        )),
    }
}

fn parse_packet_capture_start(arguments: &[String]) -> Result<Value, Value> {
    let mut interface = None;
    let mut output = None;
    let mut bursts = None;
    let mut backend = "dpdk".to_owned();
    let mut protocol = None;
    let mut source_ip = None;
    let mut destination_ip = None;
    let mut source_port = None;
    let mut destination_port = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| cli_error(&format!("missing value for {flag}")))?;
        match flag {
            "--interface" if interface.is_none() => interface = Some(value.clone()),
            "--output" if output.is_none() => output = Some(value.clone()),
            "--bursts" if bursts.is_none() => {
                bursts = Some(parse_nonzero::<u64>(value, "capture burst count")?);
            }
            "--backend" if value == "dpdk" && backend == "dpdk" => backend.clone_from(value),
            "--protocol" if protocol.is_none() => protocol = Some(value.clone()),
            "--source-ip" if source_ip.is_none() => source_ip = Some(value.clone()),
            "--destination-ip" if destination_ip.is_none() => destination_ip = Some(value.clone()),
            "--source-port" if source_port.is_none() => {
                source_port = Some(parse_u16(value, "source port")?);
            }
            "--destination-port" if destination_port.is_none() => {
                destination_port = Some(parse_u16(value, "destination port")?);
            }
            _ => {
                return Err(cli_error(&format!(
                    "unknown or duplicate packet capture option: {flag}"
                )));
            }
        }
        index += 2;
    }
    Ok(json!({
        "interface": interface.ok_or_else(|| cli_error("packet capture start requires --interface"))?,
        "output": output.ok_or_else(|| cli_error("packet capture start requires --output"))?,
        "bursts": bursts.ok_or_else(|| cli_error("packet capture start requires --bursts"))?,
        "backend": backend,
        "protocol": protocol,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
    }))
}

fn parse_u16(value: &str, name: &str) -> Result<u16, Value> {
    value
        .parse::<u16>()
        .map_err(|_| cli_error(&format!("{name} must be between 0 and 65535")))
}

fn parse_node_pair(arguments: &[String]) -> Result<Value, Value> {
    let mut node_id = None;
    let mut name = None;
    let mut address = None;
    let mut server_name = None;
    let mut fingerprint = None;
    let mut certificate_path = None;
    let mut out_of_band_fingerprint_confirmed = false;
    let mut identity_change_confirmed = false;
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        if flag == "--confirm-identity-change" {
            if identity_change_confirmed {
                return Err(cli_error("duplicate --confirm-identity-change"));
            }
            identity_change_confirmed = true;
            index += 1;
            continue;
        }
        if flag == "--confirm-fingerprint" {
            if out_of_band_fingerprint_confirmed {
                return Err(cli_error("duplicate --confirm-fingerprint"));
            }
            out_of_band_fingerprint_confirmed = true;
            index += 1;
            continue;
        }
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| cli_error(&format!("missing value for {flag}")))?;
        match flag {
            "--id" if node_id.is_none() => node_id = Some(value.clone()),
            "--name" if name.is_none() => name = Some(value.clone()),
            "--address" if address.is_none() => address = Some(value.clone()),
            "--server-name" if server_name.is_none() => server_name = Some(value.clone()),
            "--fingerprint" if fingerprint.is_none() => fingerprint = Some(value.clone()),
            "--certificate" if certificate_path.is_none() => certificate_path = Some(value.clone()),
            "--id" | "--name" | "--address" | "--server-name" | "--fingerprint"
            | "--certificate" => {
                return Err(cli_error(&format!("duplicate node pair option: {flag}")));
            }
            _ => return Err(cli_error(&format!("unknown node pair option: {flag}"))),
        }
        index += 2;
    }
    let certificate_path =
        certificate_path.ok_or_else(|| cli_error("node pair requires --certificate"))?;
    if !out_of_band_fingerprint_confirmed {
        return Err(cli_error(
            "node pair requires --confirm-fingerprint after out-of-band verification",
        ));
    }
    let certificate_der = fs::read(&certificate_path)
        .map_err(|error| cli_error(&format!("node certificate cannot be read: {error}")))?;
    Ok(json!({
        "node_id": node_id.ok_or_else(|| cli_error("node pair requires --id"))?,
        "name": name.ok_or_else(|| cli_error("node pair requires --name"))?,
        "control_address": address.ok_or_else(|| cli_error("node pair requires --address"))?,
        "server_name": server_name.ok_or_else(|| cli_error("node pair requires --server-name"))?,
        "fingerprint": fingerprint.ok_or_else(|| cli_error("node pair requires --fingerprint"))?,
        "certificate_der": certificate_der,
        "out_of_band_fingerprint_confirmed": out_of_band_fingerprint_confirmed,
        "identity_change_confirmed": identity_change_confirmed,
    }))
}

fn parse_speed_run(arguments: &[String]) -> Result<Value, Value> {
    let node = arguments
        .first()
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| cli_error("speed run requires a remote node name or ID"))?;
    let mut protocol = "tcp";
    let mut backend = "socket";
    let mut direction = "upload";
    let mut duration_ms = 10_000_u64;
    let mut warmup_ms = 1_000_u64;
    let mut cooldown_ms = 1_000_u64;
    let mut streams: Option<u16> = None;
    let mut frame_size: Option<u16> = None;
    let mut target_rate_bps: Option<u64> = None;
    let mut auto_tune = false;
    let mut latency_under_load = false;
    let mut cpus: Option<Vec<u32>> = None;
    let mut numa_node: Option<u32> = None;
    let mut accelerated_pci_address: Option<String> = None;
    let mut accelerated_interface_name: Option<String> = None;
    let mut remote_accelerated_pci_address: Option<String> = None;
    let mut remote_mac_address: Option<String> = None;
    let mut seen = BTreeSet::new();
    let mut index = 1;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        if !seen.insert(flag) {
            return Err(cli_error(&format!("duplicate speed option: {flag}")));
        }
        if flag == "--auto-tune" {
            auto_tune = true;
            index += 1;
            continue;
        }
        if flag == "--latency-under-load" {
            latency_under_load = true;
            index += 1;
            continue;
        }
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| cli_error(&format!("missing value for {flag}")))?;
        match flag {
            "--protocol" if matches!(value.as_str(), "tcp" | "udp" | "raw") => protocol = value,
            "--backend"
                if matches!(
                    value.as_str(),
                    "socket" | "native" | "dpdk" | "af_xdp" | "rio"
                ) =>
            {
                backend = value;
            }
            "--direction" if matches!(value.as_str(), "upload" | "download" | "bidirectional") => {
                direction = value;
            }
            "--duration" => duration_ms = parse_duration_ms(value)?,
            "--warmup" => warmup_ms = parse_duration_ms(value)?,
            "--cooldown" => cooldown_ms = parse_duration_ms(value)?,
            "--streams" if value == "auto" => streams = None,
            "--streams" => streams = Some(parse_nonzero::<u16>(value, "stream count")?),
            "--frame-size" => {
                frame_size = Some(parse_nonzero::<u16>(value, "frame size")?);
            }
            "--rate" => target_rate_bps = Some(parse_rate_bps(value)?),
            "--cpus" if value == "auto" => cpus = None,
            "--cpus" => cpus = Some(parse_cpu_set(value)?),
            "--numa" if value == "auto" => numa_node = None,
            "--numa" => numa_node = Some(parse_nonzero_or_zero::<u32>(value, "NUMA node")?),
            "--pci" => accelerated_pci_address = Some(value.clone()),
            "--interface" => accelerated_interface_name = Some(value.clone()),
            "--remote-pci" => remote_accelerated_pci_address = Some(value.clone()),
            "--remote-mac" => remote_mac_address = Some(value.clone()),
            _ => {
                return Err(cli_error(&format!(
                    "unknown or invalid speed option: {flag}"
                )));
            }
        }
        index += 2;
    }
    Ok(json!({
        "node": node,
        "protocol": protocol,
        "backend": backend,
        "direction": direction,
        "duration_ms": duration_ms,
        "warmup_ms": warmup_ms,
        "cooldown_ms": cooldown_ms,
        "streams": streams,
        "frame_size": frame_size,
        "target_rate_bps": target_rate_bps,
        "auto_tune": auto_tune,
        "latency_under_load": latency_under_load,
        "cpus": cpus,
        "numa_node": numa_node,
        "accelerated_pci_address": accelerated_pci_address,
        "accelerated_interface_name": accelerated_interface_name,
        "remote_accelerated_pci_address": remote_accelerated_pci_address,
        "remote_mac_address": remote_mac_address,
    }))
}

fn parse_duration_ms(value: &str) -> Result<u64, Value> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else {
        return Err(cli_error("duration requires ms, s, or m suffix"));
    };
    parse_nonzero::<u64>(number, "duration")?
        .checked_mul(multiplier)
        .ok_or_else(|| cli_error("duration overflow"))
}

fn parse_rate_bps(value: &str) -> Result<u64, Value> {
    let (number, multiplier) = match value.chars().last() {
        Some('K' | 'k') => (&value[..value.len() - 1], 1_000_u64),
        Some('M' | 'm') => (&value[..value.len() - 1], 1_000_000),
        Some('G' | 'g') => (&value[..value.len() - 1], 1_000_000_000),
        Some('T' | 't') => (&value[..value.len() - 1], 1_000_000_000_000),
        _ => (value, 1),
    };
    parse_nonzero::<u64>(number, "target rate")?
        .checked_mul(multiplier)
        .ok_or_else(|| cli_error("target rate overflow"))
}

fn parse_cpu_set(value: &str) -> Result<Vec<u32>, Value> {
    let mut cpus = Vec::new();
    for item in value.split(',') {
        if let Some((start, end)) = item.split_once('-') {
            let start = parse_nonzero_or_zero::<u32>(start, "CPU ID")?;
            let end = parse_nonzero_or_zero::<u32>(end, "CPU ID")?;
            if start > end || u64::from(end - start) > 65_535 {
                return Err(cli_error("CPU range is invalid or too large"));
            }
            cpus.extend(start..=end);
        } else {
            cpus.push(parse_nonzero_or_zero::<u32>(item, "CPU ID")?);
        }
    }
    if cpus.is_empty() {
        return Err(cli_error("CPU set must not be empty"));
    }
    let mut unique = cpus.clone();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != cpus.len() {
        return Err(cli_error("CPU set contains duplicate IDs"));
    }
    Ok(cpus)
}

fn parse_nonzero<T>(value: &str, name: &str) -> Result<T, Value>
where
    T: std::str::FromStr + Default + PartialEq,
{
    let parsed = value
        .parse::<T>()
        .map_err(|_| cli_error(&format!("{name} is invalid")))?;
    if parsed == T::default() {
        return Err(cli_error(&format!("{name} must be non-zero")));
    }
    Ok(parsed)
}

fn parse_nonzero_or_zero<T>(value: &str, name: &str) -> Result<T, Value>
where
    T: std::str::FromStr,
{
    value
        .parse::<T>()
        .map_err(|_| cli_error(&format!("{name} is invalid")))
}

fn cli_error(message: &str) -> Value {
    json!({"code":"CLI.INVALID_ARGUMENT","message":message,"retryable":false})
}

fn request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{counter}", std::process::id())
}

fn human_output(action: &str, value: &Value) -> String {
    match action {
        "system.health" => format!(
            "Agent: {}\nDatabase schema: {}",
            value["status"].as_str().unwrap_or("unknown"),
            value["schema_version"]
        ),
        "profile.list" => value.as_array().map_or_else(
            || "Profiles: unavailable".to_owned(),
            |profiles| format!("Profiles: {}", profiles.len()),
        ),
        _ => serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_args, split_dry_run};
    use serde_json::json;

    #[test]
    fn maps_cli_to_action() {
        assert_eq!(
            parse_args(["profile", "list"].into_iter().map(str::to_owned)).expect("valid command"),
            ("profile.list", false, json!({}))
        );
    }

    #[test]
    fn maps_packet_capture_lifecycle_commands() {
        assert_eq!(
            parse_args(
                [
                    "packet",
                    "capture",
                    "start",
                    "--interface",
                    "0000:01:00.0",
                    "--output",
                    "/tmp/nettool-capture",
                    "--bursts",
                    "4"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .expect("capture start"),
            (
                "packet.capture.start",
                false,
                json!({"interface":"0000:01:00.0","output":"/tmp/nettool-capture","bursts":4,"backend":"dpdk","protocol":null,"source_ip":null,"destination_ip":null,"source_port":null,"destination_port":null})
            )
        );
        assert_eq!(
            parse_args(
                [
                    "packet",
                    "capture",
                    "stop",
                    "00112233445566778899aabbccddeeff"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .expect("capture stop"),
            (
                "packet.capture.stop",
                false,
                json!({"session_id":"00112233445566778899aabbccddeeff"})
            )
        );
    }

    #[test]
    fn maps_packet_connections_filter() {
        assert_eq!(
            parse_args(
                ["packet", "connections", "--protocol", "tcp"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("connections"),
            ("packet.connections", false, json!({"protocol":"tcp"}))
        );
        assert!(
            parse_args(
                ["packet", "connections", "--protocol", "icmp"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_err()
        );
    }

    #[test]
    fn maps_speed_history_limit() {
        assert_eq!(
            parse_args(
                ["speed", "history", "--limit", "25"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("history"),
            ("speed.history", false, json!({"limit":25}))
        );
    }

    #[test]
    fn extracts_global_dry_run_flag_and_rejects_duplicates() {
        let (dry_run, arguments) = split_dry_run(
            ["profile", "apply", "--dry-run", "--interface", "eth0"]
                .into_iter()
                .map(str::to_owned),
        )
        .expect("dry-run flag");
        assert!(dry_run);
        assert_eq!(arguments, ["profile", "apply", "--interface", "eth0"]);
        assert!(
            split_dry_run(
                ["health", "--dry-run", "--dry-run"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_err()
        );
    }

    #[test]
    fn maps_speed_history_csv_format() {
        assert_eq!(
            parse_args(
                ["speed", "history", "--limit", "2", "--format", "csv"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("history csv"),
            ("speed.history", false, json!({"limit":2,"format":"csv"}))
        );
        assert_eq!(
            parse_args(
                ["speed", "history", "--format", "csv", "--limit", "2"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("reordered history csv"),
            ("speed.history", false, json!({"limit":2,"format":"csv"}))
        );
        assert!(
            parse_args(
                ["speed", "history", "--format", "csv", "--format", "csv"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_err()
        );
    }

    #[test]
    fn maps_interface_commands() {
        assert_eq!(
            parse_args(["interface", "list"].into_iter().map(str::to_owned)).expect("list"),
            ("interface.list", false, json!({}))
        );
        assert_eq!(
            parse_args(["interface", "show", "eth0"].into_iter().map(str::to_owned)).expect("show"),
            ("interface.show", false, json!({"name_or_id":"eth0"}))
        );
    }

    #[test]
    fn maps_quick_network_commands() {
        assert_eq!(
            parse_args(
                [
                    "ip",
                    "set",
                    "--interface",
                    "eth0",
                    "--address",
                    "192.0.2.10",
                    "--prefix",
                    "24",
                    "--gateway",
                    "192.0.2.1"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .expect("ip set"),
            (
                "ip.set",
                false,
                json!({"interface_id":"eth0","address":"192.0.2.10","prefix_length":24,"gateway":"192.0.2.1","confirm_timeout_seconds":null})
            )
        );
        assert_eq!(
            parse_args(
                ["ip", "dhcp", "--interface", "eth0"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("ip dhcp"),
            (
                "ip.dhcp",
                false,
                json!({"interface_id":"eth0","confirm_timeout_seconds":null})
            )
        );
        assert_eq!(
            parse_args(
                [
                    "dns",
                    "set",
                    "--interface",
                    "eth0",
                    "--server",
                    "1.1.1.1",
                    "--server",
                    "8.8.8.8"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .expect("dns set"),
            (
                "dns.set",
                false,
                json!({"interface_id":"eth0","servers":["1.1.1.1","8.8.8.8"],"confirm_timeout_seconds":null})
            )
        );
    }

    #[test]
    fn maps_node_inventory_commands() {
        assert_eq!(
            parse_args(["node", "list"].into_iter().map(str::to_owned)).expect("node list"),
            ("node.list", false, json!({}))
        );
        assert_eq!(
            parse_args(["node", "status"].into_iter().map(str::to_owned)).expect("node status"),
            ("node.status", false, json!({}))
        );
    }

    #[test]
    fn rejects_duplicate_node_pair_fields() {
        let error = parse_args(
            [
                "node",
                "pair",
                "--id",
                "00112233445566778899aabbccddeeff",
                "--id",
                "ffeeddccbbaa99887766554433221100",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect_err("duplicate pairing fields must fail");
        assert_eq!(error["message"], "duplicate node pair option: --id");
    }

    #[test]
    fn maps_packet_analyze_command() {
        assert_eq!(
            parse_args(
                [
                    "packet",
                    "analyze",
                    "--input",
                    "capture.pcap",
                    "--sample-one-in",
                    "10"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .expect("packet analyze"),
            (
                "packet.analyze",
                false,
                json!({"input":"capture.pcap","sample_one_in":10})
            )
        );
    }

    #[test]
    fn maps_packet_stats_command() {
        assert_eq!(
            parse_args(
                ["packet", "stats", "--interface", "eth0"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("packet stats"),
            ("packet.stats", false, json!({"interface_id":"eth0"}))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn maps_profile_crud_commands() {
        assert_eq!(
            parse_args(["profile", "show", "lab"].into_iter().map(str::to_owned)).expect("show"),
            ("profile.show", false, json!({"id_or_name":"lab"}))
        );
        assert_eq!(
            parse_args(
                ["profile", "confirm", "op-1"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("confirm"),
            ("profile.confirm", false, json!({"operation_id":"op-1"}))
        );
        assert_eq!(
            parse_args(
                [
                    "hosts",
                    "replace",
                    "lab",
                    r#"[{"address":"192.0.2.1","hostname":"server.local"}]"#
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .expect("hosts"),
            (
                "hosts.replace",
                false,
                json!({"profile_id":"lab","entries":[{"address":"192.0.2.1","hostname":"server.local"}]})
            )
        );
        assert_eq!(
            parse_args(
                [
                    "profile",
                    "apply",
                    "lab",
                    "--interface",
                    "eth0",
                    "--confirm-timeout",
                    "30"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .expect("apply"),
            (
                "profile.apply",
                false,
                json!({"id_or_name":"lab","interface_id":"eth0","confirm_timeout_seconds":30})
            )
        );
        assert_eq!(
            parse_args(
                ["profile", "create", "lab", "Lab", r#"{"version":1}"#]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("create"),
            (
                "profile.create",
                false,
                json!({"id":"lab","name":"Lab","configuration":{"version":1}})
            )
        );
        assert_eq!(
            parse_args(
                ["profile", "edit", "lab", "Lab 2", r#"{"version":2}"#]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("edit"),
            (
                "profile.edit",
                false,
                json!({"id_or_name":"lab","name":"Lab 2","configuration":{"version":2}})
            )
        );
        assert_eq!(
            parse_args(["profile", "export", "lab"].into_iter().map(str::to_owned))
                .expect("export"),
            ("profile.export", false, json!({"id_or_name":"lab"}))
        );
        assert_eq!(
            parse_args(
                ["hosts", "add", "lab", "192.0.2.10", "api.lab", "managed"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("hosts add"),
            (
                "hosts.add",
                false,
                json!({"profile_id":"lab","address":"192.0.2.10","hostname":"api.lab","comment":"managed"})
            )
        );
        assert_eq!(
            parse_args(
                ["hosts", "remove", "lab", "api.lab"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("hosts remove"),
            (
                "hosts.remove",
                false,
                json!({"profile_id":"lab","hostname":"api.lab"})
            )
        );
        assert_eq!(
            parse_args(
                ["hosts", "disable", "lab", "api.lab"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("hosts disable"),
            (
                "hosts.disable",
                false,
                json!({"profile_id":"lab","hostname":"api.lab"})
            )
        );
    }

    #[test]
    fn accepts_json_as_global_suffix() {
        assert_eq!(
            parse_args(
                ["health", "--output", "json"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("valid command"),
            ("system.health", true, json!({}))
        );
    }

    #[test]
    fn maps_performance_discovery_commands() {
        assert_eq!(
            parse_args(["perf", "topology"].into_iter().map(str::to_owned)).expect("topology"),
            ("perf.topology", false, json!({}))
        );
        assert_eq!(
            parse_args(["perf", "backend"].into_iter().map(str::to_owned)).expect("backend"),
            ("perf.backend", false, json!({}))
        );
    }

    #[test]
    fn benchmark_command_carries_profile_payload() {
        assert_eq!(
            parse_args(
                ["perf", "benchmark", "--profile", "100g-cert"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .expect("benchmark"),
            ("perf.benchmark", false, json!({"profile":"100g-cert"}))
        );
    }

    #[test]
    fn speed_run_parses_raw_dpdk_contract_and_units() {
        let (action, output, payload) = parse_args(
            [
                "speed",
                "run",
                "node-b",
                "--protocol",
                "raw",
                "--backend",
                "dpdk",
                "--frame-size",
                "64",
                "--rate",
                "100G",
                "--duration",
                "10s",
                "--cpus",
                "4-6,8",
                "--numa",
                "1",
                "--output",
                "json",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("speed run");
        assert_eq!(action, "speed.run");
        assert!(output);
        assert_eq!(payload["target_rate_bps"], 100_000_000_000_u64);
        assert_eq!(payload["duration_ms"], 10_000_u64);
        assert_eq!(payload["cpus"], json!([4, 5, 6, 8]));
        assert_eq!(payload["numa_node"], 1);
    }

    #[test]
    fn speed_cancel_carries_session_id_payload() {
        let (action, output, payload) = parse_args(
            [
                "speed",
                "cancel",
                "00112233445566778899aabbccddeeff",
                "--output",
                "json",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("cancel");
        assert_eq!(action, "speed.cancel");
        assert!(output);
        assert_eq!(payload["session_id"], "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn speed_run_rejects_duplicate_options_and_invalid_units() {
        assert!(
            parse_args(
                ["speed", "run", "node-b", "--duration", "10"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_err()
        );
        assert!(
            parse_args(
                [
                    "speed",
                    "run",
                    "node-b",
                    "--protocol",
                    "tcp",
                    "--protocol",
                    "udp",
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .is_err()
        );
    }
}
