# ADR-0007: Packet accounting and confidence

狀態：Accepted

每個 packet worker 使用私有 counters，statistics worker 低頻合併。NIC、driver、capture、ring、analyzer、application drop 與 network inferred loss 必須分欄呈現；被動 capture 不填入 inferred network loss。

只有 capture、ring、analyzer drop 皆為零且 required flow state 完整時才可標記 HIGH。POC threshold 尚未正式凍結時，存在 drop 的結果保守標記 LOW，不在程式碼內捏造百分比。
