import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../ui/app.js', import.meta.url), 'utf8');

// DOM 替身只承接文字與事件；真正的 HTML/CSP 另以瀏覽器 smoke test 驗證。
class Element {
    children = [];
    listeners = new Map();
    textContent = '';
    value = '';
    hidden = false;
    disabled = false;
    content = 'test-token';
    set innerHTML(value) { this.html = value; }
    appendChild(child) { this.children.push(child); }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    addEventListener(name, listener) { this.listeners.set(name, listener); }
    setAttribute() {}
    querySelectorAll() { return [new Element(), new Element()]; }
}

async function harness(handler = () => ({ success: true, data: {} }), saved = new Map()) {
    const elements = new Map();
    const element = selector => {
        if (!elements.has(selector)) elements.set(selector, new Element());
        return elements.get(selector);
    };
    const requests = [];
    let now = 1_800_000_000_000;
    const context = vm.createContext({
        document: { querySelector: element, querySelectorAll: () => [], createElement: () => new Element() },
        sessionStorage: {
            getItem: key => saved.get(key) ?? null,
            setItem: (key, value) => saved.set(key, value),
            removeItem: key => saved.delete(key),
        },
        crypto: { randomUUID },
        Date: class extends Date { static now() { return now; } },
        setInterval() {},
        setTimeout: callback => callback(),
        window: { confirm: () => true },
        fetch: async (path, options) => {
            if (path === '/api/actions') return { json: async () => [] };
            const body = JSON.parse(options.body);
            requests.push({ path, options, body });
            const result = await handler(body, path);
            return { ok: true, json: async () => result };
        },
    });
    vm.runInContext(source, context);
    await new Promise(resolve => setImmediate(resolve));
    requests.length = 0;
    element('#profile-interface').value = 'Ethernet';
    element('#profile-timeout').value = '60';
    return {
        element, requests, saved,
        run: code => vm.runInContext(code, context),
        advance: seconds => { now += seconds * 1000; vm.runInContext('updateSafeApply()', context); },
    };
}

function helperResult(body, path) {
    if (path === '/api/portable-helper') return { success: true, mode: 'external' };
    if (body.action === 'profile.apply') return { success: true, data: {
        operation_id: body.operation_id, state: 'pending_confirmation',
        target_interface: 'Ethernet', deadline_unix_seconds: 1_800_000_060,
    }};
    if (body.action === 'profile.confirm') return { success: true, data: {
        operation_id: body.payload.operation_id, state: 'confirmed',
    }};
    if (body.action === 'profile.rollback') return { success: true, data: { rolled_back: true } };
    return { success: true, data: {} };
}

test('Apply → Confirm carries the original operation and clears pending state only on success', async () => {
    const app = await harness(helperResult);
    await app.run("showProfile('office')");
    await app.run('applySelectedProfile()');
    const apply = app.requests.find(request => request.body.action === 'profile.apply');
    assert.ok(apply.body.operation_id.startsWith('gui-'));
    assert.equal(app.element('#safe-apply-confirm').disabled, false);
    assert.equal(app.element('#profile-apply').disabled, true);
    await app.run('finishSafeApply("profile.confirm")');
    const confirm = app.requests.find(request => request.body.action === 'profile.confirm');
    assert.equal(confirm.body.payload.operation_id, apply.body.operation_id);
    assert.equal(app.saved.size, 0);
    assert.equal(app.element('#safe-apply-panel').hidden, true);
    assert.match(app.element('#safe-apply-notice').textContent, /已確認/);
    for (const request of app.requests) {
        assert.equal(request.options.headers['X-NetTool-CSRF'], 'test-token');
        assert.equal(request.options.headers['Content-Type'], 'application/json');
    }
});

test('reload preserves rollback target, and navigation does not discard pending operation', async () => {
    const first = await harness(helperResult);
    await first.run("showProfile('office')");
    await first.run('applySelectedProfile()');
    const id = first.requests.find(request => request.body.action === 'profile.apply').body.operation_id;
    const reloaded = await harness(helperResult, first.saved);
    await reloaded.run('render("Environment")');
    assert.equal(reloaded.element('#safe-apply-panel').hidden, false);
    await reloaded.run('finishSafeApply("profile.rollback")');
    assert.equal(reloaded.requests.at(-1).body.payload.operation_id, id);
    assert.match(reloaded.element('#safe-apply-notice').textContent, /Helper 已完成回復/);
});

test('deadline disables Confirm without claiming rollback completion', async () => {
    const app = await harness(helperResult);
    await app.run("showProfile('office')");
    await app.run('applySelectedProfile()');
    app.advance(61);
    const count = app.requests.length;
    await app.run('finishSafeApply("profile.confirm")');
    assert.equal(app.requests.length, count);
    assert.equal(app.element('#safe-apply-confirm').disabled, true);
    assert.equal(app.element('#safe-apply-rollback').disabled, false);
    assert.match(app.element('#safe-apply-status').textContent, /尚未取得回復完成證據/);
    assert.equal(app.saved.size, 1);
});

test('lost Apply response preserves operation ID and never auto-reapplies after an unknown failure', async () => {
    const app = await harness((body, path) => {
        if (body.action === 'profile.apply') throw new Error('connection lost');
        return helperResult(body, path);
    });
    await app.run("showProfile('office')");
    await app.run('applySelectedProfile()');
    await app.run('applySelectedProfile()');
    assert.equal(app.requests.filter(request => request.body.action === 'profile.apply').length, 1);
    assert.equal(app.element('#safe-apply-confirm').disabled, true);
    assert.equal(app.saved.size, 1);
    await app.run('finishSafeApply("profile.rollback")');
    assert.equal(app.saved.size, 0);
});

test('UAC readiness retry retains the exact Apply operation ID and payload', async () => {
    let attempts = 0;
    const app = await harness((body, path) => {
        if (body.action === 'profile.apply' && attempts++ === 0) {
            return { success: false, error: { code: 'HELPER.TRANSPORT_FAILED', retryable: true } };
        }
        return helperResult(body, path);
    });
    await app.run("showProfile('office')");
    await app.run('applySelectedProfile()');
    const applies = app.requests.filter(request => request.body.action === 'profile.apply');
    assert.equal(applies.length, 2);
    assert.deepEqual(applies[0].body, applies[1].body);
    assert.equal(app.element('#safe-apply-confirm').disabled, false);
});

test('failed Confirm retains recovery controls and never reports completion', async () => {
    const app = await harness((body, path) => body.action === 'profile.confirm'
        ? { success: false, error: { message: 'helper disconnected' } } : helperResult(body, path));
    await app.run("showProfile('office')");
    await app.run('applySelectedProfile()');
    await app.run('finishSafeApply("profile.confirm")');
    assert.equal(app.saved.size, 1);
    assert.equal(app.element('#safe-apply-rollback').disabled, false);
    assert.match(app.element('#safe-apply-notice').textContent, /操作結果尚未確認/);
});

test('HTML-looking result is rendered as text, not HTML', async () => {
    const app = await harness();
    app.run(`showResult(content, 'Node', { name: '<img src=x onerror=alert(1)>' })`);
    const output = app.element('#content').children[1];
    assert.match(output.textContent, /<img src=x onerror=alert\(1\)>/);
    assert.equal(output.html, undefined);
});

test('a late Dashboard response cannot replace a newer page', async () => {
    let release;
    const app = await harness((body) => {
        if (body.action === 'system.health') return new Promise(resolve => { release = resolve; });
        return { success: true, data: { environment: true } };
    });
    await app.run('render("Environment")');
    release({ success: true, data: { dashboard: true } });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(app.element('#page').textContent, 'Environment');
    assert.match(app.element('#content').children[1].textContent, /environment/);
});
