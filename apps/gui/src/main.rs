//! 跨平台 localhost GUI；所有業務操作仍經既有 Agent Action API。

#![forbid(unsafe_code)]

use nettool_action::ActionRegistry;
use nettool_agent_client::{default_socket_path, request};
use nettool_agent_protocol::{
    ActionRequest, AgentEnvelope, PROTOCOL_MAJOR, PROTOCOL_MINOR, agent_envelope,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_HTTP_REQUEST_BYTES: usize = 64 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 48 * 1024;
const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:8765";
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static HEALTH_PATH: OnceLock<String> = OnceLock::new();

const INDEX_HTML: &str = include_str!("../ui/index.html");

#[derive(Debug, Deserialize)]
struct ActionCall {
    action: String,
    #[serde(default)]
    payload: Value,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let address = std::env::var("NETTOOL_GUI_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN_ADDRESS.to_owned())
        .parse::<SocketAddr>()?;
    if !address.ip().is_loopback() {
        return Err("NETTOOL_GUI_LISTEN must bind to a loopback address".into());
    }
    let listener = TcpListener::bind(address).await?;
    let _ = HEALTH_PATH
        .set(std::env::var("NETTOOL_GUI_HEALTH_PATH").unwrap_or_else(|_| "/health".to_owned()));
    tracing::info!(operation = "gui.listen", peer = %address, "nettool-gui listening");
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream).await {
                tracing::error!(operation = "gui.request", error = %error, "GUI request failed");
            }
        });
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn serve_connection(
    mut stream: TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let request = read_http_request(&mut stream).await?;
    let response = route(request).await;
    write_http_response(&mut stream, response).await?;
    Ok(())
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

async fn read_http_request(
    stream: &mut TcpStream,
) -> Result<HttpRequest, Box<dyn std::error::Error + Send + Sync>> {
    let mut bytes = Vec::with_capacity(4096);
    let header_end = loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err("HTTP request ended before headers".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_HTTP_HEADER_BYTES {
            return Err("HTTP headers exceed bound".into());
        }
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or("HTTP request line is missing")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or("HTTP method is missing")?
        .to_owned();
    let path = request_parts
        .next()
        .ok_or("HTTP path is missing")?
        .to_owned();
    if request_parts.next().is_none() {
        return Err("HTTP version is missing".into());
    }
    let mut content_length = 0_usize;
    for line in lines {
        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length = value.trim().parse()?;
        }
    }
    if content_length > MAX_HTTP_BODY_BYTES {
        return Err("HTTP body exceeds bound".into());
    }
    while bytes.len() - header_end < content_length {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err("HTTP body ended before Content-Length".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_HTTP_REQUEST_BYTES {
            return Err("HTTP request exceeds bound".into());
        }
    }
    Ok(HttpRequest {
        method,
        path,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

struct HttpResponse {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

async fn route(request: HttpRequest) -> HttpResponse {
    if request.method == "GET" && HEALTH_PATH.get().is_some_and(|path| path == &request.path) {
        return json_response("200 OK", json!({"service":"nettool-gui","status":"ok"}));
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/" | "/index.html") => text_response(
            "200 OK",
            "text/html; charset=utf-8",
            INDEX_HTML.as_bytes().to_vec(),
        ),
        ("GET", "/api/actions") => {
            let actions = ActionRegistry::all()
                .iter()
                .map(|descriptor| {
                    json!({
                        "name": descriptor.name,
                        "permission": format!("{:?}", descriptor.permission),
                        "idempotent": descriptor.idempotent,
                        "cli": descriptor.cli,
                    })
                })
                .collect::<Vec<_>>();
            json_response("200 OK", json!(actions))
        }
        ("POST", "/api/action") => match serde_json::from_slice::<ActionCall>(&request.body) {
            Ok(call) => execute_action(call).await,
            Err(error) => json_response(
                "400 Bad Request",
                json!({"success":false,"error":{"code":"GUI.INVALID_JSON","message":error.to_string()}}),
            ),
        },
        ("POST", "/api/portable-helper") => start_portable_helper(),
        _ => text_response(
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found".to_vec(),
        ),
    }
}

async fn execute_action(call: ActionCall) -> HttpResponse {
    let Some(descriptor) = ActionRegistry::find(&call.action) else {
        return json_response(
            "400 Bad Request",
            json!({"success":false,"error":{"code":"ACTION.UNKNOWN","message":"action is not registered"}}),
        );
    };
    let request_id = request_id();
    let started = Instant::now();
    tracing::info!(request_id = %request_id, action = %call.action, operation = "gui.action", "GUI action started");
    let envelope = AgentEnvelope {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        request_id: request_id.clone(),
        payload: Some(agent_envelope::Payload::Request(ActionRequest {
            action: descriptor.name.to_owned(),
            payload_json: match serde_json::to_vec(&call.payload) {
                Ok(payload) => payload,
                Err(error) => {
                    return json_response(
                        "400 Bad Request",
                        json!({"success":false,"error":{"code":"GUI.INVALID_JSON","message":error.to_string()}}),
                    );
                }
            },
            operation_id: if descriptor.idempotent {
                String::new()
            } else {
                request_id.clone()
            },
            dry_run: false,
        })),
    };
    let response = match request(&default_socket_path(), &envelope).await {
        Ok(response) if response.request_id == request_id => match response.payload {
            Some(agent_envelope::Payload::Response(response)) if response.success => {
                let data =
                    serde_json::from_slice::<Value>(&response.data_json).unwrap_or(Value::Null);
                json_response(
                    "200 OK",
                    json!({"success":true,"request_id":request_id,"data":data}),
                )
            }
            Some(agent_envelope::Payload::Response(response)) => json_response(
                "200 OK",
                json!({"success":false,"request_id":request_id,"error":{"code":response.error_code,"message":response.error_message,"retryable":response.retryable}}),
            ),
            _ => json_response(
                "502 Bad Gateway",
                json!({"success":false,"error":{"code":"AGENT.INVALID_MESSAGE","message":"agent response payload is invalid"}}),
            ),
        },
        Ok(_) => json_response(
            "502 Bad Gateway",
            json!({"success":false,"error":{"code":"AGENT.REQUEST_MISMATCH","message":"agent response request ID does not match"}}),
        ),
        Err(error) => json_response(
            "503 Service Unavailable",
            json!({"success":false,"error":{"code":error.code.as_str(),"message":error.message,"retryable":error.retryable}}),
        ),
    };
    tracing::info!(request_id = %request_id, operation = "gui.action", elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), "GUI action completed");
    response
}

fn start_portable_helper() -> HttpResponse {
    match std::env::var("NETTOOL_HELPER_MODE").as_deref() {
        Ok("external") => json_response(
            "200 OK",
            json!({"success":true,"mode":"external","message":"configured Helper will be used"}),
        ),
        Ok("portable-uac") => match portable_helper_arguments() {
            Ok((binary, arguments)) => {
                match nettool_platform_auth::launch_elevated(&binary, &arguments) {
                    Ok(()) => json_response(
                        "202 Accepted",
                        json!({"success":true,"mode":"portable-uac","message":"UAC Helper launch requested"}),
                    ),
                    Err(error) => json_response(
                        "403 Forbidden",
                        json!({"success":false,"error":{"code":"HELPER.UAC_REJECTED","message":error}}),
                    ),
                }
            }
            Err(error) => json_response(
                "409 Conflict",
                json!({"success":false,"error":{"code":"HELPER.PORTABLE_INVALID","message":error}}),
            ),
        },
        _ => json_response(
            "409 Conflict",
            json!({"success":false,"error":{"code":"HELPER.REQUIRED","message":"This portable bundle cannot apply profiles. Install the Helper MSI or use the portable UAC bundle."}}),
        ),
    }
}

fn portable_helper_arguments() -> Result<(PathBuf, Vec<String>), String> {
    let binary = PathBuf::from(required_environment("NETTOOL_PORTABLE_HELPER_BINARY")?);
    let pipe = required_environment("NETTOOL_PORTABLE_HELPER_PIPE")?;
    let state_directory = PathBuf::from(required_environment("NETTOOL_PORTABLE_HELPER_STATE_DIR")?);
    if !binary.is_file()
        || !binary
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("nettool-helper.exe"))
    {
        return Err("portable Helper binary is unavailable".to_owned());
    }
    if !pipe.starts_with(r"\\.\pipe\NetTool.Helper.Portable.") || pipe.len() > 240 {
        return Err("portable Helper pipe is invalid".to_owned());
    }
    if !state_directory.is_absolute() {
        return Err("portable Helper state directory is invalid".to_owned());
    }
    let sid = nettool_platform_auth::current_user_sid()
        .map_err(|error| format!("cannot determine current user SID: {error}"))?;
    let hosts_path = nettool_platform_auth::windows_hosts_path()
        .map_err(|error| format!("cannot determine Windows Hosts path: {error}"))?;
    Ok((
        binary,
        vec![
            "--pipe".to_owned(),
            pipe,
            "--allow-sid".to_owned(),
            sid,
            "--state-dir".to_owned(),
            state_directory.display().to_string(),
            "--hosts-file".to_owned(),
            hosts_path.display().to_string(),
            "--idle-timeout-seconds".to_owned(),
            "120".to_owned(),
        ],
    ))
}

fn required_environment(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is missing"))
}

fn request_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("gui-{timestamp:032x}-{counter:016x}")
}

#[allow(clippy::needless_pass_by_value)]
fn json_response(status: &'static str, body: Value) -> HttpResponse {
    text_response(
        status,
        "application/json; charset=utf-8",
        body.to_string().into_bytes(),
    )
}

fn text_response(status: &'static str, content_type: &'static str, body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status,
        content_type,
        body,
    }
}

async fn write_http_response(
    stream: &mut TcpStream,
    response: HttpResponse,
) -> Result<(), Infallible> {
    let headers = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    let _ = stream.write_all(headers.as_bytes()).await;
    let _ = stream.write_all(&response.body).await;
    let _ = stream.flush().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::route;

    #[tokio::test]
    async fn serves_dashboard_and_action_registry() {
        let page = route(super::HttpRequest {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            body: Vec::new(),
        })
        .await;
        assert_eq!(page.status, "200 OK");
        assert!(
            String::from_utf8(page.body)
                .expect("HTML")
                .contains("NetTool Dashboard")
        );

        let actions = route(super::HttpRequest {
            method: "GET".to_owned(),
            path: "/api/actions".to_owned(),
            body: Vec::new(),
        })
        .await;
        assert_eq!(actions.status, "200 OK");
        assert!(
            String::from_utf8(actions.body)
                .expect("JSON")
                .contains("system.health")
        );
    }

    #[test]
    fn profiles_page_exposes_typed_create_and_read_controls() {
        assert!(super::INDEX_HTML.contains("profile.create"));
        assert!(super::INDEX_HTML.contains("profile.show"));
        assert!(super::INDEX_HTML.contains("profile.apply"));
        assert!(super::INDEX_HTML.contains("/api/portable-helper"));
        assert!(super::INDEX_HTML.contains("Create profile"));
    }

    #[tokio::test]
    async fn rejects_unknown_action_before_agent_connect() {
        let response = route(super::HttpRequest {
            method: "POST".to_owned(),
            path: "/api/action".to_owned(),
            body: br#"{"action":"shell.execute","payload":{}}"#.to_vec(),
        })
        .await;
        assert_eq!(response.status, "400 Bad Request");
        assert!(
            String::from_utf8(response.body)
                .expect("JSON")
                .contains("ACTION.UNKNOWN")
        );
    }
}
