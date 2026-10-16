const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function ui() {
    const filename = path.join(__dirname, '../ui/app.js');
    assert.ok(fs.existsSync(filename), 'GUI 行為模組必須可供瀏覽器與測試載入');
    return require(filename);
}

test('TCP 表單產生 Agent 接受的毫秒與 socket 選項', () => {
    assert.deepEqual(ui().buildSpeedPayload({ node: ' lab ', protocol: 'tcp', direction: 'upload', duration: '10', streams: '2', rate: '' }), {
        node: 'lab', protocol: 'tcp', backend: 'socket', direction: 'upload',
        duration_ms: 10000, warmup_ms: 1000, cooldown_ms: 1000,
        streams: 2, frame_size: null, target_rate_bps: null,
        auto_tune: false, latency_under_load: false, cpus: null, numa_node: null,
        accelerated_pci_address: null, accelerated_interface_name: null,
    });
});

test('UDP 速率換算為 bps，TCP 不接受 UDP 速率', () => {
    const values = { node: 'lab', protocol: 'udp', direction: 'bidirectional', duration: '5', streams: '1', rate: '25' };
    assert.equal(ui().buildSpeedPayload(values).target_rate_bps, 25000000);
    assert.equal(ui().buildSpeedPayload({ ...values, protocol: 'tcp' }).target_rate_bps, null);
});

test('拒絕缺少 Node、無效時間、stream、速率與未支援選項', () => {
    const values = { node: 'lab', protocol: 'udp', direction: 'upload', duration: '10', streams: '1', rate: '10' };
    const api = ui();
    for (const invalid of [{ node: ' ' }, { duration: '0' }, { duration: '1.5' }, { streams: '65536' }, { streams: '0' }, { rate: 'NaN' }, { rate: '-1' }, { protocol: 'raw' }, { direction: 'invalid' }]) {
        assert.throws(() => api.buildSpeedPayload({ ...values, ...invalid }));
    }
});

test('離線分析使用本機路徑，完整分析省略取樣，拒絕越界取樣', () => {
    const api = ui();
    assert.deepEqual(api.buildAnalyzePayload({ input: ' D:\\capture.pcapng ', sample: '1' }), { input: 'D:\\capture.pcapng', sample_one_in: null });
    assert.deepEqual(api.buildAnalyzePayload({ input: '/tmp/capture.pcap', sample: '10' }), { input: '/tmp/capture.pcap', sample_one_in: 10 });
    for (const sample of ['0', '1.5', '4294967296', '']) {
        assert.throws(() => api.buildAnalyzePayload({ input: 'capture.pcap', sample }));
    }
    assert.throws(() => api.buildAnalyzePayload({ input: ' ', sample: '1' }));
});

test('Safe Apply 使用 Helper operation ID 而非 GUI request ID', () => {
    const api = ui();
    assert.equal(api.safeApplyOperation({ success: true, request_id: 'gui-request', data: { operation_id: 'helper-operation' } }), 'helper-operation');
    assert.throws(() => api.safeApplyOperation({ success: true, request_id: 'gui-request', data: {} }));
});

test('API 保留 Agent 錯誤碼並說明未設定 Helper', async () => {
    const api = ui();
    const transport = async () => ({ ok: false, status: 503, json: async () => ({ success: false, error: { code: 'HELPER.NOT_CONFIGURED', message: 'privileged helper socket is not configured' } }) });
    await assert.rejects(api.requestAction('hosts.read', {}, transport), /HELPER.NOT_CONFIGURED.*Helper/);
});

test('API 網路錯誤與非 JSON 回應提供可採取行動的訊息', async () => {
    const api = ui();
    await assert.rejects(api.requestAction('system.health', {}, async () => { throw new Error('offline'); }), /連線.*GUI/);
    await assert.rejects(api.requestAction('system.health', {}, async () => ({ ok: false, status: 502, json: async () => { throw new Error('HTML'); } })), /502.*JSON/);
});

test('Safe Apply 僅接受 Helper 實際確認與回復成功格式', () => {
    const api = ui();
    assert.equal(api.safeApplyCompleted('profile.confirm', { state: 'confirmed' }), true);
    assert.equal(api.safeApplyCompleted('profile.rollback', { rolled_back: true }), true);
    assert.equal(api.safeApplyCompleted('profile.confirm', { state: 'pending_confirmation' }), false);
    assert.equal(api.safeApplyCompleted('profile.rollback', { rolled_back: false }), false);
    assert.equal(api.safeApplyCompleted('profile.rollback', {}), false);
});

test('API 成功回傳原始 envelope 並送出正確 action 與 payload', async () => {
    const envelope = { success: true, request_id: 'id', data: [] };
    let sent;
    const result = await ui().requestAction('speed.history', { limit: 20 }, async (url, options) => {
        sent = { url, ...options };
        return { ok: true, status: 200, json: async () => envelope };
    });
    assert.deepEqual(result, envelope);
    assert.equal(sent.url, '/api/action');
    assert.equal(sent.method, 'POST');
    assert.deepEqual(JSON.parse(sent.body), { action: 'speed.history', payload: { limit: 20 } });
});
