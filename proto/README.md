# Protocol definitions

Agent、Helper 與遠端 Node 協定分開維護。`node.proto` 保存 Node control envelope 的公開 wire reference；目前實際 Rust wire layer 已支援 protocol minor 1，包括 dynamic source/receive ports 與可重試的 `TestResultRequest`。修改欄位或 tag 前須依 ADR 與相容性測試流程審查。
