# ADR-0001: Repository bootstrap

狀態：Accepted

P0 先建立 Rust workspace、核心模型、穩定錯誤模型與 `nettool-dataplane probe`。DPDK EAL、RX/TX、Agent、Helper 與 GUI 留在各自里程碑，避免在硬體 POC 前固定未經量測的參數。

