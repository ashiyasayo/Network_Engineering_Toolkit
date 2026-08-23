# ADR-0006: Agent-owned Resource Manager

狀態：Accepted

所有高速 session 在 helper preparation 或 dataplane launch 前，必須由 Agent 的單一 Resource Manager 原子取得完整 reservation。任何 claim 衝突都不保留部分資源，並回傳 resource、owner session 與 requested mode。

DPDK port/queue、pinned worker CPU、lossless capture writer 與 data port 強制 exclusive。計量型 shared resource 沒有明確 capacity 時拒絕 reservation，不採無界預設值。Failed reservation 仍持有 claims，直到 recovery 完成 release。
