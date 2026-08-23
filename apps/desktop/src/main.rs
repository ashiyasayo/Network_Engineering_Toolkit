#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

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
        parent.join("../Resources").join(&filename),
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
    let mut children = Vec::with_capacity(2);
    children.push(
        Command::new(agent)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("cannot start nettool-agent: {error}"))?,
    );
    children.push(
        Command::new(gui)
            .env("NETTOOL_GUI_LISTEN", "127.0.0.1:8765")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("cannot start nettool-gui: {error}"))?,
    );
    Ok(children)
}

fn wait_for_gui() {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", 8765)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
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
            let processes = spawn_runtime().map_err(std::io::Error::other)?;
            app.manage(RuntimeProcesses(Mutex::new(processes)));
            wait_for_gui();
            WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::External("http://127.0.0.1:8765".parse().expect("valid GUI URL")),
            )
            .title("NetTool")
            .inner_size(1440.0, 960.0)
            .min_inner_size(1024.0, 700.0)
            .resizable(true)
            .build()?;
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
