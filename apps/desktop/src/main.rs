//! `NetTool` 的 Tauri 原生桌面殼層與 runtime process lifecycle。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};

struct RuntimeProcesses(Mutex<Vec<Child>>);
static HEALTH_COUNTER: AtomicU64 = AtomicU64::new(0);

struct PortableHelperConfiguration {
    binary: PathBuf,
    pipe: String,
    state_directory: PathBuf,
}

fn health_token() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    let counter = HEALTH_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{timestamp:032x}-{counter:016x}")
}

fn sibling_binary(name: &str, resource_dir: Option<&Path>) -> Option<PathBuf> {
    let current = std::env::current_exe().ok()?;
    let parent = current.parent()?;
    let filename = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let mut candidates = Vec::with_capacity(7);
    if let Some(resource_dir) = resource_dir {
        candidates.push(resource_dir.join(&filename));
        candidates.push(resource_dir.join("resources").join(&filename));
    }
    candidates.extend([
        parent.join(&filename),
        parent.join("resources").join(&filename),
        parent.join("../Resources").join(&filename),
        parent.join("../resources").join(&filename),
        parent.join("../lib/nettool").join(&filename),
    ]);
    candidates.into_iter().find(|path| path.is_file())
}

fn configured_binary(name: &str, resource_dir: Option<&Path>) -> Result<PathBuf, String> {
    let variable = format!("NETTOOL_{}_BINARY", name.replace('-', "_").to_uppercase());
    if let Ok(value) = std::env::var(&variable) {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!("{variable} does not point to a file"));
    }
    sibling_binary(name, resource_dir).ok_or_else(|| format!("cannot locate bundled {name} binary"))
}

fn portable_helper_configuration(
    resource_dir: Option<&Path>,
    session_token: &str,
) -> Option<PortableHelperConfiguration> {
    #[cfg(windows)]
    {
        let binary = sibling_binary("nettool-helper", resource_dir)?;
        let state_root = std::env::var_os("LOCALAPPDATA")?;
        let state_directory = PathBuf::from(state_root)
            .join("NetTool")
            .join("portable-helper")
            .join(session_token);
        Some(PortableHelperConfiguration {
            binary,
            pipe: format!(r"\\.\pipe\NetTool.Helper.Portable.{session_token}"),
            state_directory,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (resource_dir, session_token);
        None
    }
}

fn installed_helper_pipe() -> Option<String> {
    #[cfg(windows)]
    {
        let program_data = std::env::var_os("ProgramData")?;
        let marker = PathBuf::from(program_data)
            .join("NetTool")
            .join("Helper")
            .join("helper-installed.marker");
        marker
            .is_file()
            .then(|| r"\\.\pipe\NetTool.Helper.Service".to_owned())
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn spawn_runtime(resource_dir: Option<&Path>) -> Result<(Vec<Child>, SocketAddr, String), String> {
    let agent = configured_binary("nettool-agent", resource_dir)?;
    let gui = configured_binary("nettool-gui", resource_dir)?;
    let dataplane = configured_binary("nettool-dataplane", resource_dir)?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("cannot reserve GUI loopback port: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("cannot read reserved GUI port: {error}"))?;
    drop(listener);
    let health_path = format!("/health-{}", health_token());
    let session_token = health_token();
    let configured_helper_pipe = std::env::var("NETTOOL_HELPER_SOCKET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(installed_helper_pipe);
    let portable_helper = if configured_helper_pipe.is_none() {
        portable_helper_configuration(resource_dir, &session_token)
    } else {
        None
    };
    let helper_pipe = configured_helper_pipe.or_else(|| {
        portable_helper
            .as_ref()
            .map(|configuration| configuration.pipe.clone())
    });
    let helper_mode = if portable_helper.is_some() {
        "portable-uac"
    } else if helper_pipe.is_some() {
        "external"
    } else {
        "required"
    };
    let mut children = Vec::with_capacity(2);
    let mut agent_command = Command::new(agent);
    agent_command
        .env("NETTOOL_DATAPLANE_BIN", &dataplane)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(pipe) = &helper_pipe {
        agent_command.env("NETTOOL_HELPER_SOCKET", pipe);
    }
    let agent_child = agent_command
        .spawn()
        .map_err(|error| format!("cannot start nettool-agent: {error}"))?;
    children.push(agent_child);
    let mut gui_command = Command::new(gui);
    gui_command
        .env("NETTOOL_GUI_LISTEN", address.to_string())
        .env("NETTOOL_GUI_HEALTH_PATH", &health_path)
        .env("NETTOOL_HELPER_MODE", helper_mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(configuration) = &portable_helper {
        gui_command
            .env("NETTOOL_PORTABLE_HELPER_BINARY", &configuration.binary)
            .env("NETTOOL_PORTABLE_HELPER_PIPE", &configuration.pipe)
            .env(
                "NETTOOL_PORTABLE_HELPER_STATE_DIR",
                &configuration.state_directory,
            );
    }
    match gui_command.spawn() {
        Ok(child) => children.push(child),
        Err(error) => {
            for child in &mut children {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(format!("cannot start nettool-gui: {error}"));
        }
    }
    Ok((children, address, health_path))
}

fn gui_health_check(address: SocketAddr, health_path: &str) -> bool {
    let Ok(mut stream) = TcpStream::connect(address) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
    if stream
        .write_all(
            format!("GET {health_path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .is_err()
    {
        return false;
    }
    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() {
        return false;
    }
    let response = String::from_utf8_lossy(&response);
    response.starts_with("HTTP/1.1 200 OK") && response.contains("\"service\":\"nettool-gui\"")
}

fn wait_for_gui(
    children: &mut [Child],
    address: SocketAddr,
    health_path: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if gui_health_check(address, health_path) {
            return Ok(());
        }
        if children
            .iter_mut()
            .any(|child| child.try_wait().ok().flatten().is_some())
        {
            return Err("NetTool runtime process exited before GUI became ready".to_owned());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("NetTool GUI did not pass health check before timeout".to_owned())
}

fn stop_runtime(processes: &RuntimeProcesses) {
    if let Ok(mut children) = processes.0.lock() {
        for child in &mut *children {
            let _ = child.kill();
            let _ = child.wait();
        }
        children.clear();
    }
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let resource_dir = app.path().resource_dir().ok();
            let (mut processes, address, health_path) =
                spawn_runtime(resource_dir.as_deref()).map_err(std::io::Error::other)?;
            if let Err(error) = wait_for_gui(&mut processes, address, &health_path) {
                for child in &mut processes {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                return Err(std::io::Error::other(error).into());
            }
            let window = WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::External(format!("http://{address}").parse().expect("valid GUI URL")),
            )
            .title("NetTool")
            .inner_size(1440.0, 960.0)
            .min_inner_size(1024.0, 700.0)
            .resizable(true)
            .build();
            if let Err(error) = window {
                for child in &mut processes {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                return Err(error.into());
            }
            app.manage(RuntimeProcesses(Mutex::new(processes)));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building NetTool desktop shell")
        .run(|app, event| {
            if matches!(event, RunEvent::Exit) {
                if let Some(processes) = app.try_state::<RuntimeProcesses>() {
                    stop_runtime(&processes);
                }
            }
        });
}
