//! `NetTool` 的 Tauri 原生桌面殼層與 runtime process lifecycle。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};

struct RuntimeProcesses(Mutex<Vec<Child>>);

fn sibling_binary(name: &str) -> Option<PathBuf> {
    let current = std::env::current_exe().ok()?;
    let parent = current.parent()?;
    let filename = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let candidates = [
        parent.join(&filename),
        parent.join("resources").join(&filename),
        parent.join("../Resources").join(&filename),
        parent.join("../resources").join(&filename),
        parent.join("../lib/nettool").join(&filename),
    ];
    candidates.into_iter().find(|path| path.is_file())
}

fn configured_binary(name: &str) -> Result<PathBuf, String> {
    let variable = format!("NETTOOL_{}_BINARY", name.replace('-', "_").to_uppercase());
    if let Ok(value) = std::env::var(&variable) {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!("{variable} does not point to a file"));
    }
    sibling_binary(name).ok_or_else(|| format!("cannot locate bundled {name} binary"))
}

fn spawn_runtime() -> Result<Vec<Child>, String> {
    let agent = configured_binary("nettool-agent")?;
    let gui = configured_binary("nettool-gui")?;
    let dataplane = configured_binary("nettool-dataplane")?;
    if TcpStream::connect(("127.0.0.1", 8765)).is_ok() {
        return Err("NetTool GUI port 8765 is already in use".to_owned());
    }
    let mut children = Vec::with_capacity(2);
    let agent_child = Command::new(agent)
        .env("NETTOOL_DATAPLANE_BIN", &dataplane)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("cannot start nettool-agent: {error}"))?;
    children.push(agent_child);
    match Command::new(gui)
        .env("NETTOOL_GUI_LISTEN", "127.0.0.1:8765")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => children.push(child),
        Err(error) => {
            for child in &mut children {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(format!("cannot start nettool-gui: {error}"));
        }
    }
    Ok(children)
}

fn gui_health_check() -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", 8765)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
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

fn wait_for_gui(children: &mut [Child]) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if gui_health_check() {
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
            let mut processes = spawn_runtime().map_err(std::io::Error::other)?;
            if let Err(error) = wait_for_gui(&mut processes) {
                for child in &mut processes {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                return Err(std::io::Error::other(error).into());
            }
            let window = WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::External("http://127.0.0.1:8765".parse().expect("valid GUI URL")),
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
