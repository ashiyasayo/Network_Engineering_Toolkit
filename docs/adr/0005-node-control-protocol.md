# ADR-0005: Node control protocol v1

狀態：Accepted

Node control 使用 TCP、mutual TLS 1.3、固定 12-byte NTCP header 與 Protobuf envelope。Data-plane benchmark payload 不通過 TLS control stream。Frame payload 上限固定為 1 MiB，v1 flags 與 reserved 必須為零。

Protocol 與 capability 分別版本化；identity 以完整 SHA-256 fingerprint 持久化，相同 Node ID 的 key 變更必須拒絕並重新 pairing。
