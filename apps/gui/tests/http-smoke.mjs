import assert from 'node:assert/strict';
import net from 'node:net';

// 對已啟動的隔離 GUI 執行；只送未知 action 或被安全 gate 拒絕的請求。
const base = new URL(process.argv[2] || 'http://127.0.0.1:18765');
assert.equal(base.protocol, 'http:');
assert.ok(['127.0.0.1', '[::1]'].includes(base.hostname));
const home = await fetch(base);
assert.equal(home.status, 200);
assert.equal(home.headers.get('x-frame-options'), 'DENY');
assert.equal(home.headers.get('x-content-type-options'), 'nosniff');
assert.match(home.headers.get('content-security-policy'), /script-src 'self';/);
const html = await home.text();
const token = html.match(/name="nettool-csrf" content="([a-f0-9]{64})"/)?.[1];
assert.ok(token, 'server must inject a random token');
const script = await fetch(new URL('/app.js', base));
assert.equal(script.status, 200);
assert.match(script.headers.get('content-type'), /javascript/);
assert.match(await script.text(), /showResult/);

const headers = {
    Origin: base.origin,
    'Content-Type': 'application/json',
    'X-NetTool-CSRF': token,
};
for (const path of ['/api/action', '/api/portable-helper']) {
    for (const change of [
        { Origin: 'https://attacker.invalid' },
        { 'X-NetTool-CSRF': 'incorrect' },
        { Origin: 'null' },
    ]) {
        const response = await fetch(new URL(path, base), {
            method: 'POST', headers: { ...headers, ...change }, body: '{}',
        });
        assert.equal(response.status, 403);
    }
}
const plain = await fetch(new URL('/api/action', base), {
    method: 'POST', headers: { ...headers, 'Content-Type': 'text/plain' }, body: '{}',
});
assert.equal(plain.status, 415);
const unknown = await fetch(new URL('/api/action', base), {
    method: 'POST', headers, body: JSON.stringify({ action: 'shell.execute', payload: {} }),
});
assert.equal(unknown.status, 400);
assert.equal((await unknown.json()).error.code, 'ACTION.UNKNOWN');

async function exchange(raw) {
    return new Promise((resolve, reject) => {
        const client = net.connect({
            host: base.hostname.replace(/[\[\]]/g, ''), port: Number(base.port),
        });
        let response = '';
        client.setTimeout(8000, () => client.destroy(new Error('smoke test timed out')));
        client.on('connect', () => client.write(raw));
        client.on('data', chunk => { response += chunk.toString(); });
        client.on('end', () => resolve(response));
        client.on('error', reject);
    });
}
const badHost = await exchange('GET / HTTP/1.1\r\nHost: attacker.invalid\r\n\r\n');
assert.match(badHost, /^HTTP\/1.1 403 /);
const duplicate = await exchange('POST /api/action HTTP/1.1\r\nContent-Length: 0\r\ncontent-length: 1\r\n\r\n');
assert.match(duplicate, /^HTTP\/1.1 400 /);
const slow = await exchange('POST /api/action HTTP/1.1\r\nHost: ');
assert.match(slow, /^HTTP\/1.1 408 /);
console.log('GUI HTTP smoke passed: CSP, token, Origin, Host, content type, framing and slow client timeout.');
