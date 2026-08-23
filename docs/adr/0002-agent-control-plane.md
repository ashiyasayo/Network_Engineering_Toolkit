# ADR-0002: Agent control plane baseline

狀態：Accepted

CLI 不直接呼叫 backend 或開啟 SQLite，而是以 length-prefixed Protobuf envelope 經 user-only Unix socket 呼叫 `nettool-agent`。Action payload 暫以 JSON bytes 承載，讓 envelope 與 Action schema 分別演進；frame 固定限制為 1 MiB，避免本機惡意 client 造成無界配置。

Windows Agent transport 已實作 Named Pipe；在 Windows runner 完成實機編譯與安全測試前，不宣稱跨平台控制平面 production-ready。Helper transport 仍需等價的 token/SID authentication。
