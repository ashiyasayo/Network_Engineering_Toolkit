# ADR-0004: Compatibility socket speed engine

狀態：Accepted

一般平台先由 TCP/UDP socket engine 提供功能性測速；DPDK、AF_XDP 與 RIO 是獨立 accelerated backends，不以 socket 測試結果宣稱 100G certified。

TCP measurement 重複使用預先配置 buffer，warm-up bytes 不納入 sender 主要結果。Socket UDP 使用包含完整 session ID、timestamp 與 payload length 的 52-byte v1 header；16-byte compact header 僅供最小 frame/accelerated benchmark。高速 software pacing 使用累積 batch budget，禁止逐 packet sleep。
