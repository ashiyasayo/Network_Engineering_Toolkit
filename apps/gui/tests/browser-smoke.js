// 由 Playwright MCP 載入此函式；API 全部攔截，不修改主機網路或信任資料。
async (page) => {
    const requests = [], errors = [], checks = [];
    const base = 'http://127.0.0.1:18765';
    const configuration = { ipv4: { mode: 'dhcp' }, ipv6: { mode: 'automatic' }, dns: { automatic: true, servers: [], search_domains: [] }, routes: [], mtu: null };
    let profiles = [], confirmFails = true, unhealthy = false;
    const session = { session_id: 'a'.repeat(32), remote_node: 'lab', protocol: 'tcp', backend: 'socket', direction: 'upload', started_at: '2026-10-16T00:00:00Z', completed_at: null, state: 'running' };
    const onError = error => errors.push(error.message);
    page.on('pageerror', onError);
    const assert = (condition, text) => { if (!condition) throw new Error(text); };
    const nav = name => page.locator(`nav [data-page="${name}"]`).click();
    const actionCount = name => requests.filter(item => item.action === name).length;
    const respond = (route, data) => route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
    const handler = async route => {
        const url = new URL(route.request().url());
        if (url.pathname === '/api/actions') return respond(route, [
            { name: 'system.health', permission: 'ReadOnly', idempotent: true, server_only: false, cli: 'nettool health' },
            { name: 'perf.topology', permission: 'ReadOnly', idempotent: true, server_only: true, cli: 'nettool perf topology' },
        ]);
        assert(/^[a-f0-9]{64}$/.test(route.request().headers()['x-nettool-csrf'] || ''), 'POST 未帶入同源權杖');
        if (url.pathname === '/api/portable-helper') return respond(route, { success: true, mode: 'external' });
        const request = route.request().postDataJSON(); requests.push(request);
        const { action, payload } = request;
        let data;
        switch (action) {
            case 'system.health':
                if (unhealthy) return respond(route, { success: false, error: { code: 'AGENT.UNAVAILABLE', message: 'agent is not running' } });
                data = { status: 'healthy', schema_version: 1 }; break;
            case 'interface.list': data = { schema_version: '1.0', interfaces: [{ name: '<img src=x onerror=alert(1)>', ip_addresses: ['192.0.2.1'], link_speed_mbps: null, driver: null, bus_type: 'unknown', pci_address: null, rx_queues: null, tx_queues: null, numa_node: null }] }; break;
            case 'node.status': data = { schema_version: '1.0', nodes: [{ id: 'b'.repeat(32), name: 'lab', last_address: '192.0.2.10:9443', fingerprint: 'verified', server_name: 'lab', control_address: '192.0.2.10:9443', state: 'trusted' }] }; break;
            case 'node.pair': data = { paired: true, node_id: payload.node_id, name: payload.name, control_address: payload.control_address, fingerprint: payload.fingerprint }; break;
            case 'speed.history': data = [session]; break;
            case 'speed.run': data = { session_id: session.session_id, state: 'COMPLETED' }; break;
            case 'profile.list': data = profiles; break;
            case 'profile.create': profiles = [{ id: payload.id, name: payload.name, active_revision: 1 }]; data = profiles[0]; break;
            case 'profile.show': data = { summary: profiles[0], configuration }; break;
            case 'profile.apply': data = { operation_id: request.operation_id, target_interface: payload.interface_id, snapshot_id: 'snapshot', deadline_unix_seconds: Math.floor(Date.now() / 1000) + 60, state: 'pending_confirmation', old_state_hash: 'old', new_state_hash: 'new' }; break;
            case 'profile.confirm':
                if (confirmFails) return respond(route, { success: false, error: { code: 'HELPER.TRANSPORT_FAILED', message: 'helper offline', retryable: true } });
                data = { operation_id: payload.operation_id, state: 'confirmed' }; break;
            case 'profile.rollback': data = { rolled_back: true }; break;
            case 'packet.analyze': data = { schema_version: '1.0', backend: 'offline_capture', input: payload.input, bursts: 1, analysis: { coverage: payload.sample_one_in ? 'sampled' : 'full', sample_one_in: payload.sample_one_in }, statistics: {} }; break;
            case 'hosts.read': return respond(route, { success: false, error: { code: 'HELPER.NOT_CONFIGURED', message: 'privileged helper socket is not configured' } });
            default: throw new Error(`未預期的 Action：${action}`);
        }
        return respond(route, { success: true, request_id: 'gui-request', data });
    };
    await page.route(`${base}/api/**`, handler);
    try {
        await page.goto(base);
        await page.evaluate(() => sessionStorage.removeItem('nettool.pending-safe-apply'));
        await page.reload();
        await page.evaluate(() => { window.__testOriginalConfirm = window.confirm; window.confirm = () => true; });
        await page.getByText('Agent 運作正常', { exact: true }).waitFor(); checks.push('健康狀態');
        await nav('interfaces'); await page.locator('table tbody tr').waitFor();
        assert(await page.locator('table').innerText().then(text => text.includes('<img src=x') && text.includes('未提供')), '介面欄位錯誤');
        assert(await page.locator('#content img').count() === 0, 'API 文字被當成 HTML'); checks.push('介面表格與安全文字');
        await nav('nodes'); await page.locator('table tbody tr').waitFor(); assert((await page.locator('table').innerText()).includes('192.0.2.10:9443'), 'Node 表格未顯示控制位址'); checks.push('Node 表格');
        await page.locator('#node_id').fill('b'.repeat(32)); await page.locator('#name').fill('lab'); await page.locator('#control_address').fill('192.0.2.10:9443');
        await page.locator('#server_name').fill('lab'); await page.locator('#fingerprint').fill('verified');
        await page.locator('#certificate').setInputFiles({ name: 'test.der', mimeType: 'application/octet-stream', buffer: Buffer.from([48, 3, 1, 2, 3]) });
        await page.getByRole('button', { name: '配對 Node', exact: true }).click();
        assert(actionCount('node.pair') === 0, '未核對指紋仍送出配對');
        await page.locator('[name="fingerprint_confirmed"]').check(); await page.getByRole('button', { name: '配對 Node', exact: true }).click();
        await page.getByText('Node 已配對。', { exact: true }).waitFor();
        const pairing = requests.find(item => item.action === 'node.pair').payload;
        assert(pairing.out_of_band_fingerprint_confirmed === true && pairing.identity_change_confirmed === false && pairing.certificate_der.join(',') === '48,3,1,2,3', '配對 payload 錯誤'); checks.push('Node 配對與指紋確認');
        await nav('speed'); await page.locator('#node').fill('lab'); await page.getByRole('button', { name: '開始測速', exact: true }).click();
        await page.getByText('測速已完成，可重新整理查看最新歷史。', { exact: true }).waitFor();
        let payload = requests.find(item => item.action === 'speed.run').payload;
        assert(payload.duration_ms === 10000 && payload.backend === 'socket' && payload.target_rate_bps === null, 'TCP payload 錯誤');
        await page.locator('#protocol').selectOption('udp'); await page.locator('#rate').fill('25'); await page.getByRole('button', { name: '開始測速', exact: true }).click();
        await page.getByText('測速已完成，可重新整理查看最新歷史。', { exact: true }).waitFor();
        payload = requests.filter(item => item.action === 'speed.run').at(-1).payload; assert(payload.target_rate_bps === 25000000, 'UDP 速率未換算');
        const speedCount = actionCount('speed.run'); await page.locator('#duration').fill('0'); await page.getByRole('button', { name: '開始測速', exact: true }).click();
        assert(actionCount('speed.run') === speedCount, '無效測速表單仍發出請求'); checks.push('TCP／UDP 與表單驗證');
        await nav('packets'); await page.locator('#input').fill('D:\\capture.pcap'); await page.locator('#sample').fill('10'); await page.getByRole('button', { name: '分析檔案', exact: true }).click();
        await page.getByText('取樣分析完成；統計僅涵蓋取樣封包。', { exact: true }).waitFor();
        assert(requests.find(item => item.action === 'packet.analyze').payload.sample_one_in === 10, '取樣參數錯誤');
        await page.locator('#sample').fill('1'); await page.getByRole('button', { name: '分析檔案', exact: true }).click(); await page.getByText('完整分析完成。', { exact: true }).waitFor(); checks.push('完整／取樣分析');
        await nav('profiles'); await page.locator('#profile-id').fill('office'); await page.locator('#profile-name').fill('辦公室');
        await page.locator('#profile-configuration').fill('[]'); await page.getByRole('button', { name: '建立 Profile', exact: true }).click();
        await page.getByText('網路設定必須是 JSON object。', { exact: true }).waitFor(); assert(actionCount('profile.create') === 0, '無效設定仍保存');
        await page.locator('#profile-configuration').fill(JSON.stringify(configuration)); await page.getByRole('button', { name: '建立 Profile', exact: true }).click();
        await page.getByText('Profile 已建立，尚未套用。', { exact: true }).waitFor();
        await page.locator('#profile-apply').waitFor(); await page.waitForFunction(() => !document.querySelector('#profile-apply').disabled);
        await page.locator('#profile-interface').fill('Ethernet'); await page.locator('#profile-apply').click();
        await page.getByText('已套用，請使用頁面上方 Safe Apply 確認或回復。', { exact: true }).waitFor();
        const operationId = requests.find(item => item.action === 'profile.apply').operation_id;
        assert(operationId?.startsWith('gui-') && await page.locator('#operation-id').inputValue() === operationId, '使用了錯誤的 operation ID');
        assert(await page.locator('#profile-apply').isDisabled(), '待確認操作未停用 Apply');
        await page.reload();
        await page.evaluate(() => { window.__testOriginalConfirm = window.confirm; window.confirm = () => true; });
        assert(await page.locator('#operation-id').inputValue() === operationId, '重新整理遺失 Safe Apply');
        await nav('interfaces'); assert(await page.locator('#safe-apply').isVisible(), '切換頁面遺失 Safe Apply');
        await page.locator('#profile-confirm').click(); await page.locator('#safe-status.error').waitFor(); assert(await page.locator('#operation-id').inputValue() === operationId, '確認失敗清除了 operation ID');
        confirmFails = false; await page.locator('#profile-confirm').click(); await page.getByText('已確認保留設定。', { exact: true }).waitFor();
        await nav('profiles'); await page.locator('.profile-item').click(); await page.waitForFunction(() => !document.querySelector('#profile-apply').disabled);
        await page.locator('#profile-interface').fill('Ethernet'); await page.locator('#profile-apply').click(); await page.getByText('已套用，請使用頁面上方 Safe Apply 確認或回復。', { exact: true }).waitFor();
        await page.locator('#profile-rollback').click(); await page.getByText('已回復原設定。', { exact: true }).waitFor(); checks.push('Profile 建立與 Safe Apply 確認／失敗保留／回復');
        await nav('hosts'); await page.locator('#content .error').waitFor(); assert((await page.locator('#content').innerText()).includes('HELPER.NOT_CONFIGURED'), 'Helper 錯誤未顯示');
        unhealthy = true; await nav('dashboard'); await page.locator('#content .error').waitFor(); assert((await page.locator('#content').innerText()).includes('nettool-agent'), '未提示啟動 Agent'); checks.push('Agent／Helper 錯誤');
        await nav('help'); await page.setViewportSize({ width: 390, height: 844 });
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), '手機版出現整頁橫向溢出'); checks.push('手機版排版');
        await page.setViewportSize({ width: 1280, height: 900 }); unhealthy = false; await nav('dashboard'); await page.getByText('Agent 運作正常', { exact: true }).waitFor();
        assert(errors.length === 0, `瀏覽器錯誤：${errors.join(', ')}`);
        const result = { checks, requests: requests.length, pageErrors: errors };
        await page.evaluate(result => { window.__nettoolSmoke = result; }, result);
        return result;
    } finally {
        await page.evaluate(() => { if (window.__testOriginalConfirm) window.confirm = window.__testOriginalConfirm; });
        await page.unroute(`${base}/api/**`, handler);
        page.removeListener('pageerror', onError);
    }
}
