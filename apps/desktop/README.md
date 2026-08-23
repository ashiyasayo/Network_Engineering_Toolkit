# NetTool native desktop shell

`nettool-desktop` is the Tauri 2 native shell. It starts the bundled
`nettool-agent` and loopback-only `nettool-gui` processes, then displays the
same Action API UI in a native WebView window. The shell never performs network
or privileged operations itself.

Development:

```sh
cargo run -p nettool-desktop
```

The binary locations can be overridden for development or packaging with
`NETTOOL_NETTOOL_AGENT_BINARY` and `NETTOOL_NETTOOL_GUI_BINARY`.
