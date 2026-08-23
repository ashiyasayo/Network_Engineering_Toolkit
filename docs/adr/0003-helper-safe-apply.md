# ADR-0003: Helper owns Safe Apply deadline

狀態：Accepted

Helper 在任何網路 apply 前先建立 snapshot，並以原子檔案持久化 operation、deadline 與狀態 hash。Apply 驗證後進入 pending confirmation；confirm 取消 rollback，逾期或明確 rollback 則由 snapshot 恢復。Agent 與 UI 不是 deadline authority。

Helper API 採封閉 enum whitelist，避免新增可被濫用為任意 root command executor 的字串型命令介面。
