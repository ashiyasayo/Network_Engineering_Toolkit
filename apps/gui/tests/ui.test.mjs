import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
const { SafeApplySession } = createRequire(import.meta.url)('../ui/app.js');

// 只替換外部傳輸與持久化邊界，執行正式的交易狀態管理。
function harness(handler, saved = new Map()) {
    const requests = [];
    let now = 1_800_000_000_000;
    const storage = {
        getItem: key => saved.get(key) ?? null,
        setItem: (key, value) => saved.set(key, value),
        removeItem: key => saved.delete(key),
    };
    const session = new SafeApplySession(storage, async (action, payload, operation_id) => {
        const request = { action, payload, operation_id }; requests.push(request);
        return handler ? handler(request) : result(request);
    }, () => {}, () => now, async () => {});
    session.restore();
    return { session, requests, saved, advance: seconds => { now += seconds * 1000; } };
}
const payload = { id_or_name: 'office', interface_id: 'Ethernet', confirm_timeout_seconds: 60 };
function result(request) {
    if (request.action === 'profile.apply') return { success: true, data: {
        operation_id: request.operation_id, state: 'pending_confirmation', target_interface: 'Ethernet', deadline_unix_seconds: 1_800_000_060,
    } };
    if (request.action === 'profile.confirm') return { success: true, data: { operation_id: request.payload.operation_id, state: 'confirmed' } };
    return { success: true, data: { rolled_back: true } };
}
test('Apply → Confirm preserves operation identity and clears recovery only on success', async () => {
    const app = harness(); await app.session.apply(payload, async () => {});
    const id = app.requests[0].operation_id;
    assert.match(id, /^gui-/); assert.equal(app.session.canConfirm, true);
    await app.session.finish('profile.confirm');
    assert.equal(app.requests[1].payload.operation_id, id);
    assert.equal(app.session.pending, null); assert.equal(app.saved.size, 0);
});
test('reload and navigation retain the rollback target', async () => {
    const first = harness(); await first.session.apply(payload, async () => {});
    const id = first.session.pending.operation_id;
    const next = harness(undefined, first.saved);
    assert.equal(next.session.pending.operation_id, id);
    await next.session.finish('profile.rollback');
    assert.equal(next.requests[0].payload.operation_id, id); assert.equal(next.saved.size, 0);
});
test('deadline disables Confirm without claiming rollback completion', async () => {
    const app = harness(); await app.session.apply(payload, async () => {}); app.advance(61);
    assert.equal(app.session.canConfirm, false);
    await assert.rejects(app.session.finish('profile.confirm'), /期限|未確認/);
    assert.equal(app.requests.length, 1); assert.equal(app.saved.size, 1);
    await app.session.finish('profile.rollback'); assert.equal(app.saved.size, 0);
});
test('lost Apply response retains ID and blocks another Apply', async () => {
    const app = harness(request => { if (request.action === 'profile.apply') throw new Error('connection lost'); return result(request); });
    await assert.rejects(app.session.apply(payload, async () => {}), /connection lost/);
    await assert.rejects(app.session.apply(payload, async () => {}));
    assert.equal(app.requests.length, 1); assert.equal(app.session.canConfirm, false);
    assert.equal(app.saved.size, 1); await app.session.finish('profile.rollback'); assert.equal(app.saved.size, 0);
});
test('UAC readiness retries use exactly the same operation ID and payload', async () => {
    let attempts = 0;
    const app = harness(request => {
        if (request.action === 'profile.apply' && attempts++ === 0) throw Object.assign(new Error('not ready'), { code: 'HELPER.TRANSPORT_FAILED', retryable: true });
        return result(request);
    });
    await app.session.apply(payload, async () => {});
    assert.equal(app.requests.length, 2); assert.deepEqual(app.requests[0], app.requests[1]); assert.equal(app.session.canConfirm, true);
});
test('failed or mismatched Confirm retains recovery state', async () => {
    const app = harness(request => request.action === 'profile.confirm' ? { success: true, data: { state: 'confirmed', operation_id: 'wrong-id' } } : result(request));
    await app.session.apply(payload, async () => {});
    await assert.rejects(app.session.finish('profile.confirm'));
    assert.equal(app.saved.size, 1); assert.ok(app.session.pending);
});
test('failure to persist prevents any Apply side effects', async () => {
    let sent = 0;
    const app = new SafeApplySession({ setItem() { throw new Error('storage denied'); } }, async () => { sent++; }, () => {});
    await assert.rejects(app.apply(payload, async () => {}), /storage denied/); assert.equal(sent, 0);
});
test('malformed saved operation is rejected rather than trusted', () => {
    const saved = new Map([['nettool.pending-safe-apply', JSON.stringify({ operation_id: 'bad/id', deadline_unix_seconds: 1, target_interface: 'Ethernet', state: 'pending_confirmation' })]]);
    assert.throws(() => harness(undefined, saved));
});
