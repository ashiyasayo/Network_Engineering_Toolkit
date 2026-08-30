# Accelerated speed NIC selector

## 決策

Accelerated `speed.run` 的 canonical NIC selector 使用 PCI BDF。CLI 可接受介面名稱作為使用者輸入，但 Agent 必須在建立 Node `PrepareTest` 前，透過最新 probe snapshot 解析為唯一的 PCI BDF；wire protocol 與 executor 不得依賴可變的介面名稱。

## 原因

DPDK port、queue ownership、NUMA 與 userspace driver binding 都以 PCI 裝置為穩定邊界。介面名稱可能被重新命名、隨 OS 狀態變動，且不能可靠表達 DPDK port identity。

## 後果

- socket/native backend 不接受 accelerated NIC selector。
- accelerated backend 要求恰好一個 BDF 或可唯一解析的介面名稱。
- Node `PrepareTest` 僅傳遞已驗證的 PCI BDF。
- 無 PCI BDF、名稱不唯一或 probe 與輸入不一致時 fail closed。
