//! 跨平台 localhost GUI；所有業務操作仍經既有 Agent Action API。

#![forbid(unsafe_code)]

use nettool_action::ActionRegistry;
use nettool_agent_client::{default_socket_path, request};
use nettool_agent_protocol::{
    ActionRequest, AgentEnvelope, PROTOCOL_MAJOR, PROTOCOL_MINOR, agent_envelope,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const MAX_HTTP_REQUEST_BYTES: usize = 64 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 48 * 1024;
const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:8765";
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static HEALTH_PATH: OnceLock<String> = OnceLock::new();

const INDEX_HTML: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const HTTP_IO_TIMEOUT: Duration = Duration::from_secs(5);

type HttpError = Box<dyn std::error::Error + Send + Sync>;

struct GuiSecurity {
    authority: String,
    csrf_token: String,
}

impl GuiSecurity {
    fn new(address: SocketAddr) -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)?;
        let mut csrf_token = String::with_capacity(64);
        for byte in bytes {
            write!(csrf_token, "{byte:02x}").expect("writing into String cannot fail");
        }
        Ok(Self {
            authority: address.to_string(),
            csrf_token,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    let security = Arc::new(
        GuiSecurity::new(listener.local_addr()?)
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    );
    let connections = Arc::new(Semaphore::new(64));
    let _ = HEALTH_PATH
        .set(std::env::var("NETTOOL_GUI_HEALTH_PATH").unwrap_or_else(|_| "/health".to_owned()));
    tracing::info!(operation = "gui.listen", peer = %address, "nettool-gui listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let security = security.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = serve_connection(stream, &security).await {
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

async fn serve_connection(mut stream: TcpStream, security: &GuiSecurity) -> Result<(), HttpError> {
    let response = match tokio::time::timeout(HTTP_IO_TIMEOUT, read_http_request(&mut stream)).await
    {
        Ok(Ok(request)) => route(request, security).await,
        Ok(Err(_)) => gui_error(
            "400 Bad Request",
            "GUI.INVALID_HTTP",
            "invalid or oversized HTTP request",
        ),
        Err(_) => gui_error(
            "408 Request Timeout",
            "GUI.REQUEST_TIMEOUT",
            "HTTP request timed out",
        ),
    };
    tokio::time::timeout(HTTP_IO_TIMEOUT, write_http_response(&mut stream, response)).await??;
    Ok(())
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

// 只接受 GUI 使用的單一、定長 request；協定語法交由 httparse 處理。
fn parse_http_head(bytes: &[u8]) -> Result<Option<(HttpRequest, usize, usize)>, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    let httparse::Status::Complete(header_end) = parsed.parse(bytes)? else {
        if bytes.len() > MAX_HTTP_HEADER_BYTES {
            return Err("HTTP headers exceed bound".into());
        }
        return Ok(None);
    };
    if header_end > MAX_HTTP_HEADER_BYTES || parsed.version != Some(1) {
        return Err("HTTP headers exceed bound or version is unsupported".into());
    }
    let mut values = BTreeMap::new();
    for header in parsed.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let value = std::str::from_utf8(header.value)?.trim().to_owned();
        if values.insert(name, value).is_some() {
            return Err("duplicate HTTP header".into());
        }
    }
    if values.contains_key("transfer-encoding") {
        return Err("Transfer-Encoding is unsupported".into());
    }
    let length = values.get("content-length").map_or(Ok(0), |value| {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("Content-Length is invalid");
        }
        value
            .parse::<usize>()
            .map_err(|_| "Content-Length is invalid")
    })?;
    if length > MAX_HTTP_BODY_BYTES || header_end + length > MAX_HTTP_REQUEST_BYTES {
        return Err("HTTP body exceeds bound".into());
    }
    Ok(Some((
        HttpRequest {
            method: parsed.method.ok_or("HTTP method is missing")?.to_owned(),
            path: parsed.path.ok_or("HTTP path is missing")?.to_owned(),
            headers: values,
            body: Vec::new(),
        },
        header_end,
        length,
    )))
}

async fn read_http_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<HttpRequest, HttpError> {
    let mut bytes = Vec::with_capacity(4096);
    let (mut request, header_end, length) = loop {
        if let Some(head) = parse_http_head(&bytes)? {
            break head;
        }
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err("HTTP request ended before headers".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    let total = header_end + length;
    if bytes.len() < total {
        let received = bytes.len();
        bytes.resize(total, 0);
        stream.read_exact(&mut bytes[received..]).await?;
    }
    request.body = bytes[header_end..total].to_vec();
    Ok(request)
}

fn gui_error(status: &'static str, code: &str, message: &str) -> HttpResponse {
    json_response(
        status,
        json!({"success":false,"error":{"code":code,"message":message}}),
    )
}

fn validate_browser_request(
    request: &HttpRequest,
    security: &GuiSecurity,
) -> Result<(), HttpResponse> {
    // 固定 numeric Host，避免 DNS rebinding；連接埠也必須與 listener 一致。
    if request.header("host") != Some(security.authority.as_str()) {
        return Err(gui_error(
            "403 Forbidden",
            "GUI.INVALID_HOST",
            "GUI Host does not match listener",
        ));
    }
    if request.method == "POST" {
        let origin = format!("http://{}", security.authority);
        if request.header("origin") != Some(origin.as_str())
            || request.header("x-nettool-csrf") != Some(security.csrf_token.as_str())
        {
            return Err(gui_error(
                "403 Forbidden",
                "GUI.INVALID_ORIGIN",
                "same-origin GUI token is required",
            ));
        }
        let json = request
            .header("content-type")
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
        if !json {
            return Err(gui_error(
                "415 Unsupported Media Type",
                "GUI.INVALID_CONTENT_TYPE",
                "application/json is required",
            ));
        }
    }
    Ok(())
}

struct HttpResponse {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

async fn route(request: HttpRequest, security: &GuiSecurity) -> HttpResponse {
    if let Err(response) = validate_browser_request(&request, security) {
        return response;
    }
    if request.method == "GET" && HEALTH_PATH.get().is_some_and(|path| path == &request.path) {
        return json_response("200 OK", json!({"service":"nettool-gui","status":"ok"}));
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/" | "/index.html") => text_response(
            "200 OK",
            "text/html; charset=utf-8",
            INDEX_HTML
                .replace("__NETTOOL_CSRF_TOKEN__", &security.csrf_token)
                .into_bytes(),
        ),
        ("GET", "/app.js") => text_response(
            "200 OK",
            "text/javascript; charset=utf-8",
            APP_JS.as_bytes().to_vec(),
        ),
        ("GET", "/api/actions") => {
            let actions = ActionRegistry::all()
                .iter()
                .map(|descriptor| {
                    json!({
                        "name": descriptor.name,
                        "permission": format!("{:?}", descriptor.permission),
                        "idempotent": descriptor.idempotent,
                        "server_only": descriptor.is_server_only(),
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

fn encode_action(call: ActionCall, request_id: &str) -> Result<ActionRequest, HttpResponse> {
    let Some(descriptor) = ActionRegistry::find(&call.action) else {
        return Err(json_response(
            "400 Bad Request",
            json!({"success":false,"error":{"code":"ACTION.UNKNOWN","message":"action is not registered"}}),
        ));
    };
    let payload_json = serde_json::to_vec(&call.payload)
        .map_err(|error| gui_error("400 Bad Request", "GUI.INVALID_JSON", &error.to_string()))?;
    Ok(ActionRequest {
        action: descriptor.name.to_owned(),
        payload_json,
        operation_id: if descriptor.idempotent {
            String::new()
        } else {
            request_id.to_owned()
        },
        dry_run: false,
    })
}

async fn execute_action(call: ActionCall) -> HttpResponse {
    let request_id = request_id();
    let started = Instant::now();
    let action = match encode_action(call, &request_id) {
        Ok(action) => action,
        Err(response) => return response,
    };
    tracing::info!(request_id = %request_id, action = %action.action, operation = "gui.action", "GUI action started");
    let envelope = AgentEnvelope {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        request_id: request_id.clone(),
        payload: Some(agent_envelope::Payload::Request(action)),
    };
    let response = match request(&default_socket_path(), &envelope).await {
        Ok(response) if response.request_id == request_id => match response.payload {
            Some(agent_envelope::Payload::Response(response)) if response.success => {
                let Ok(data) = serde_json::from_slice::<Value>(&response.data_json) else {
                    return gui_error(
                        "502 Bad Gateway",
                        "AGENT.INVALID_MESSAGE",
                        "agent response JSON is invalid",
                    );
                };
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
) -> Result<(), std::io::Error> {
    let headers = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn security() -> GuiSecurity {
        GuiSecurity {
            authority: "127.0.0.1:8765".into(),
            csrf_token: "test-token".into(),
        }
    }

    fn request(method: &str, path: &str) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            body: Vec::new(),
            headers: BTreeMap::from([
                ("host".into(), "127.0.0.1:8765".into()),
                ("origin".into(), "http://127.0.0.1:8765".into()),
                ("content-type".into(), "application/json".into()),
                ("x-nettool-csrf".into(), "test-token".into()),
            ]),
        }
    }

    #[tokio::test]
    async fn serves_dashboard_script_and_action_registry() {
        let page = route(request("GET", "/"), &security()).await;
        assert_eq!(page.status, "200 OK");
        let html = String::from_utf8(page.body).expect("HTML");
        assert!(html.contains("NetTool Dashboard"));
        assert!(html.contains("content=\"test-token\""));
        assert!(!html.contains("__NETTOOL_CSRF_TOKEN__"));
        assert!(!html.contains("<script>"));
        assert_eq!(
            route(request("GET", "/app.js"), &security()).await.body,
            APP_JS.as_bytes()
        );
        let actions = route(request("GET", "/api/actions"), &security()).await;
        assert_eq!(actions.status, "200 OK");
        let actions = String::from_utf8(actions.body).expect("JSON");
        assert!(actions.contains("system.health"));
        assert!(actions.contains("\"server_only\":true"));
    }

    #[tokio::test]
    async fn rejects_cross_origin_missing_token_and_rebinding_before_dispatch() {
        for path in ["/api/action", "/api/portable-helper"] {
            for (header, value) in [
                ("host", Some("attacker.invalid:8765")),
                ("host", Some("127.0.0.1:9999")),
                ("host", None),
                ("origin", Some("https://attacker.invalid")),
                ("origin", Some("null")),
                ("origin", None),
                ("x-nettool-csrf", Some("wrong")),
                ("x-nettool-csrf", None),
            ] {
                let mut request = request("POST", path);
                if let Some(value) = value {
                    request.headers.insert(header.into(), value.into());
                } else {
                    request.headers.remove(header);
                }
                assert_eq!(
                    route(request, &security()).await.status,
                    "403 Forbidden",
                    "{path}: {header}"
                );
            }
            for value in [
                None,
                Some("text/plain"),
                Some("application/x-www-form-urlencoded"),
            ] {
                let mut request = request("POST", path);
                if let Some(value) = value {
                    request.headers.insert("content-type".into(), value.into());
                } else {
                    request.headers.remove("content-type");
                }
                assert_eq!(
                    route(request, &security()).await.status,
                    "415 Unsupported Media Type"
                );
            }
        }
        let mut get = request("GET", "/");
        get.headers
            .insert("host".into(), "attacker.invalid:8765".into());
        assert_eq!(route(get, &security()).await.status, "403 Forbidden");
    }

    #[tokio::test]
    async fn rejects_unknown_action_before_agent_connect() {
        let mut request = request("POST", "/api/action");
        request.body = br#"{"action":"shell.execute","payload":{}}"#.to_vec();
        let response = route(request, &security()).await;
        assert_eq!(response.status, "400 Bad Request");
        assert!(
            String::from_utf8(response.body)
                .expect("JSON")
                .contains("ACTION.UNKNOWN")
        );
    }

    #[tokio::test]
    async fn parses_case_insensitive_headers_and_complete_body() {
        let raw =
            b"POST /api/action HTTP/1.1\r\nhost: 127.0.0.1:8765\r\ncOnTeNt-LeNgTh: 2\r\n\r\n{}";
        let request = read_http_request(&mut raw.as_slice())
            .await
            .expect("valid HTTP");
        assert_eq!(request.header("host"), Some("127.0.0.1:8765"));
        assert_eq!(request.body, b"{}");
        let (mut writer, mut reader) = tokio::io::duplex(16);
        let sender = tokio::spawn(async move {
            for chunk in raw.chunks(3) {
                writer.write_all(chunk).await.expect("chunk");
            }
        });
        assert_eq!(
            read_http_request(&mut reader)
                .await
                .expect("fragmented request")
                .body,
            b"{}"
        );
        sender.await.expect("sender");
    }

    #[tokio::test]
    async fn rejects_ambiguous_truncated_and_oversized_framing() {
        for headers in [
            "Content-Length: 0\r\ncontent-length: 0\r\n",
            "Host: one\r\nhost: two\r\n",
            "Origin: one\r\norigin: two\r\n",
            "X-NetTool-CSRF: one\r\nx-nettool-csrf: two\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: -1\r\n",
            "Content-Length: +1\r\n",
            "Content-Length: 49153\r\n",
            "Content-Length: 999999999999999999999999999999\r\n",
            "bad header\r\n",
        ] {
            let raw = format!("POST /api/action HTTP/1.1\r\n{headers}\r\n");
            assert!(
                read_http_request(&mut raw.as_bytes()).await.is_err(),
                "{headers}"
            );
        }
        let raw = b"POST /api/action HTTP/1.1\r\nContent-Length: 3\r\n\r\n{}";
        assert!(read_http_request(&mut raw.as_slice()).await.is_err());
        let raw = format!(
            "GET / HTTP/1.1\r\nX-Large: {}\r\n\r\n",
            "a".repeat(MAX_HTTP_HEADER_BYTES)
        );
        assert!(read_http_request(&mut raw.as_bytes()).await.is_err());
    }

}
