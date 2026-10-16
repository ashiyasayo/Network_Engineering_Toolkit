/* 所有操作由 Agent 驗證；模組同時供瀏覽器與 Node 行為測試使用。 */
(function () {
    'use strict';
    function integer(value, label, min, max) {
        const number = Number(value);
        if (String(value).trim() === '' || !Number.isSafeInteger(number) || number < min || number > max) throw new Error(`${label}必須是 ${min} 至 ${max} 的整數。`);
        return number;
    }
    function required(value, label) {
        const text = String(value ?? '').trim();
        if (!text) throw new Error(`請填寫${label}。`);
        return text;
    }
    function buildSpeedPayload(values) {
        const node = required(values.node, 'Node 名稱或 ID');
        if (!['tcp', 'udp'].includes(values.protocol)) throw new Error('基本測速只支援 TCP 或 UDP。');
        if (!['upload', 'download', 'bidirectional'].includes(values.direction)) throw new Error('測試方向無效。');
        const duration = integer(values.duration, '測量秒數', 1, 3600), streams = integer(values.streams, '串流數', 1, 65535);
        let rate = null;
        if (values.protocol === 'udp') {
            rate = Number(values.rate) * 1000000;
            if (!Number.isSafeInteger(rate) || rate <= 0) throw new Error('UDP 速率必須是正數，且可換算為整數 bps。');
        }
        return { node, protocol: values.protocol, backend: 'socket', direction: values.direction,
            duration_ms: duration * 1000, warmup_ms: 1000, cooldown_ms: 1000, streams,
            frame_size: null, target_rate_bps: rate, auto_tune: false, latency_under_load: false,
            cpus: null, numa_node: null, accelerated_pci_address: null, accelerated_interface_name: null };
    }
    function buildAnalyzePayload(values) {
        const input = required(values.input, 'Agent 主機上的 PCAP／PCAPNG 路徑'), sample = integer(values.sample, '取樣間隔', 1, 4294967295);
        return { input, sample_one_in: sample === 1 ? null : sample };
    }
    function safeApplyOperation(response) {
        // request_id 只供追蹤請求，不能代替 Helper 持久化的 operation_id。
        return required(response.data?.operation_id, 'Helper 回傳的 operation_id；請保留結果並檢查 Helper 狀態');
    }
    function safeApplyCompleted(action, data) {
        return action === 'profile.confirm' ? data?.state === 'confirmed' : action === 'profile.rollback' && data?.rolled_back === true;
    }
    function agentError(error) {
        const hints = {
            'HELPER.NOT_CONFIGURED': '請安裝並設定 Helper；Windows 可使用 Helper MSI 或 UAC portable。',
            'HELPER.REQUIRED': '請安裝 Helper MSI 或改用 UAC portable。',
            'HELPER.TRANSPORT_FAILED': '請確認 Helper 已啟動；若剛接受 UAC，請稍候並檢查結果再重試。',
            'NODE.NOT_PAIRED': '請先到「Node 配對」建立可信任的測速對端。',
            'DATAPLANE.BACKEND_NOT_BUILT': '目前建置未連結所需 backend，請檢查「環境與能力」。',
        };
        return new Error(`[${error?.code || 'GUI.ACTION_FAILED'}] ${error?.message || '操作失敗。'} ${hints[error?.code] || ''}`.trim());
    }
    async function requestJson(url, options, transport = globalThis.fetch) {
        let response;
        try { response = await transport(url, options); }
        catch { throw new Error('無法連線至 GUI 服務，請確認 nettool-gui 已啟動。若正在變更設定，請先檢查結果，避免重複送出。'); }
        let data;
        try { data = await response.json(); }
        catch { throw new Error(`HTTP ${response.status} 回應不是有效 JSON，請檢查 GUI 服務。`); }
        if (data?.success === false) throw agentError(data.error);
        if (!response.ok) throw new Error(`HTTP ${response.status}：GUI 服務無法完成請求。`);
        return data;
    }
    async function requestAction(action, payload, transport) {
        const body = JSON.stringify({ action, payload });
        if (new TextEncoder().encode(body).length > 48 * 1024) throw new Error('請求超過 GUI 的 48 KiB 上限，請縮小參數或憑證。');
        const response = await requestJson('/api/action', { method: 'POST', headers: { 'content-type': 'application/json' }, body }, transport);
        if (response?.success !== true) throw new Error('Agent 回應格式無效，請檢查服務版本。');
        return response;
    }
    if (typeof module !== 'undefined' && module.exports) module.exports = { buildSpeedPayload, buildAnalyzePayload, safeApplyOperation, safeApplyCompleted, requestAction };
    if (typeof document === 'undefined') return;

    const $ = selector => document.querySelector(selector), content = $('#content'), actionMetadata = new Map();
    let currentPage = 'dashboard', speedRunning = false, applyRunning = false, safeBusy = false, pendingOperation = '';
    const pages = {
        dashboard: ['功能總覽', '查看服務狀態，選擇要執行的網路工作。'],
        interfaces: ['網路介面', '查詢 IP、驅動與速度；未知欄位顯示「未提供」。'],
        profiles: ['網路設定 Profile', '先保存設定，再選擇介面套用；建立 Profile 不會變更系統網路。'],
        hosts: ['Hosts', '讀取與變更 Hosts 都需要已設定的 Helper。'],
        speed: ['網路測速', '使用已配對的 Node 執行 socket 基本測速。'],
        packets: ['封包分析', '分析 Agent 主機上的 Ethernet PCAP／PCAPNG 檔案。'],
        nodes: ['Node 配對', '先透過獨立管道核對對端指紋，再建立信任。'],
        settings: ['環境與能力', '唯讀探測平台與 backend；探測能力不代表通過效能驗收。'],
        history: ['測速歷史', '最近 20 筆測速紀錄與終態；此頁不是系統日誌。'],
        help: ['使用說明', '從環境查詢開始，依需求設定網路或執行測試。'],
    };
    function element(tag, text, className) {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        if (className) node.className = className;
        return node;
    }
    function card(parent, title, hint) {
        const section = element('section', undefined, 'card'); section.append(element('h3', title));
        if (hint) section.append(element('p', hint, 'hint'));
        parent.append(section); return section;
    }
    function status(parent) {
        const node = element('p', '', 'status'); node.setAttribute('role', 'status'); node.setAttribute('aria-live', 'polite'); parent.append(node); return node;
    }
    function report(node, text, failed = false) { node.textContent = text; node.className = `status ${failed ? 'error' : 'success'}`; }
    function button(parent, text, handler, primary = false) {
        const node = element('button', text, primary ? 'primary' : 'secondary'); node.type = 'button';
        if (handler) node.addEventListener('click', handler);
        parent.append(node); return node;
    }
    function field(parent, name, title, value = '', options = {}) {
        const label = element('label', title), input = document.createElement(options.choices ? 'select' : options.multiline ? 'textarea' : 'input');
        input.name = name; input.id = options.id || name;
        if (options.choices) options.choices.forEach(([key, text]) => { const option = element('option', text); option.value = key; input.append(option); });
        else if (!options.multiline) input.type = options.type || 'text';
        input.value = value; input.required = options.required !== false;
        for (const key of ['min', 'max', 'step', 'placeholder', 'maxLength', 'accept']) if (options[key] !== undefined) input[key] = options[key];
        label.append(input); parent.append(label); return input;
    }
    function checkbox(parent, name, text, mustCheck = false) {
        const label = element('label', undefined, 'check'), input = document.createElement('input');
        input.type = 'checkbox'; input.name = name; input.required = mustCheck;
        label.append(input, document.createTextNode(text)); parent.append(label); return input;
    }
    function raw(parent, data, title = '檢視完整結果（JSON）') {
        const details = element('details'); details.append(element('summary', title), element('pre', JSON.stringify(data, null, 2))); parent.append(details);
    }
    function display(value) {
        if (value === null || value === undefined || value === '') return '未提供';
        return Array.isArray(value) ? (value.length ? value.join('、') : '無') : String(value);
    }
    function table(parent, rows, columns, caption, empty = '目前沒有資料。') {
        if (!rows.length) { parent.append(element('p', empty, 'hint')); return; }
        const wrap = element('div', undefined, 'table-wrap'), grid = element('table'); grid.append(element('caption', caption));
        const head = element('thead'), header = element('tr');
        columns.forEach(([title]) => { const th = element('th', title); th.scope = 'col'; header.append(th); }); head.append(header); grid.append(head);
        const body = element('tbody'); rows.forEach(row => {
            const tr = element('tr'); columns.forEach(([, key]) => tr.append(element('td', display(typeof key === 'function' ? key(row) : row[key])))); body.append(tr);
        }); grid.append(body); wrap.append(grid); parent.append(wrap);
    }
    async function query(parent, action, payload, renderResult) {
        const message = status(parent); report(message, '查詢中…');
        try { const response = await requestAction(action, payload); renderResult(response.data); message.remove(); raw(parent, response); }
        catch (error) { report(message, `${error.message} 請確認 nettool-agent 已啟動。`, true); }
    }
    function bindForm(form, submit, message, action) {
        form.addEventListener('submit', async event => {
            event.preventDefault(); if (submit.disabled) return;
            submit.disabled = true; report(message, '處理中…');
            try { await action(Object.fromEntries(new FormData(form))); }
            catch (error) { report(message, error.message, true); }
            finally { submit.disabled = false; }
        });
    }
    function formCard(parent, title, hint) { const panel = card(parent, title, hint), form = element('form'); panel.append(form); return { panel, form }; }
    function dashboard() {
        const panel = card(content, '本機服務狀態');
        query(panel, 'system.health', {}, data => {
            panel.append(element('p', data.status === 'healthy' ? 'Agent 運作正常' : display(data.status), 'metric'));
            panel.append(element('p', `資料庫 schema：${display(data.schema_version)}`, 'hint'));
        });
        const grid = element('div', undefined, 'grid'); content.append(grid);
        for (const [target, title, hint] of [
            ['interfaces', '盤點網路', '查看介面、IP 位址、驅動與硬體能力。'],
            ['profiles', '切換網路設定', '保存 Profile，透過 Safe Apply 套用及確認。'],
            ['speed', '測試連線吞吐', '先配對 Node，再執行 TCP／UDP socket 測速。'],
            ['packets', '分析封包檔案', '讀取 PCAP／PCAPNG，查看統計及取樣覆蓋率。'],
        ]) button(card(grid, title, hint), '開啟功能', () => navigate(target));
        card(content, '硬體驗收限制', 'DPDK、AF_XDP、RIO、NUMA 與高速 benchmark 屬於伺服器專用。原生 backend 與硬體未就緒時會明確失敗；目前不提供 100G Certified 宣告。');
    }
    function interfaces() {
        const panel = card(content, '介面清單');
        query(panel, 'interface.list', {}, data => table(panel, data.interfaces || [], [['名稱', 'name'], ['IP 位址', 'ip_addresses'], ['速度（Mbps）', 'link_speed_mbps'], ['驅動', 'driver'], ['匯流排', 'bus_type'], ['PCI', 'pci_address'], ['RX / TX queues', row => `${display(row.rx_queues)} / ${display(row.tx_queues)}`]], '目前可觀察的網路介面', '沒有找到網路介面。'));
    }
    const defaultConfiguration = { ipv4: { mode: 'dhcp' }, ipv6: { mode: 'automatic' }, dns: { automatic: true, servers: [], search_domains: [] }, routes: [], mtu: null };
    function profiles() {
        $('#safe-apply').hidden = false;
        const split = element('div', undefined, 'split'); content.append(split);
        const listPanel = card(split, '已保存的 Profile', '選取後讀取完整設定；建立與讀取不需要 Helper。'), list = element('div', undefined, 'profile-list'); listPanel.append(list);
        const detail = card(split, 'Profile 設定', '套用前核對目標介面。需要 Helper；UAC portable 會要求提高權限。');
        const output = element('pre', '請先選取左側的 Profile。'); output.id = 'profile-detail'; detail.append(output);
        const form = element('form'); detail.append(form);
        field(form, 'interface_id', '目標介面名稱或 ID', '', { placeholder: 'Ethernet', id: 'profile-interface' });
        field(form, 'timeout', '確認期限（秒）', '60', { type: 'number', min: 10, max: 600, id: 'profile-timeout' });
        const apply = button(form, '套用 Profile', null, true); apply.type = 'submit'; apply.id = 'profile-apply'; apply.disabled = true;
        const message = status(detail); let selected = '', selection = 0;
        async function show(id) {
            const revision = ++selection; selected = ''; apply.disabled = true; output.textContent = '讀取中…';
            try {
                const response = await requestAction('profile.show', { id_or_name: id });
                if (revision !== selection) return;
                output.textContent = JSON.stringify(response.data, null, 2); selected = id; apply.disabled = applyRunning;
            } catch (error) { if (revision === selection) report(message, error.message, true); }
        }
        async function load() {
            list.replaceChildren(element('p', '載入中…', 'hint'));
            try {
                const response = await requestAction('profile.list', {}); list.replaceChildren();
                if (!response.data.length) list.append(element('p', '尚無 Profile，請使用下方表單建立。', 'hint'));
                response.data.forEach(profile => {
                    const item = button(list, profile.name, () => show(profile.id)); item.classList.add('profile-item');
                    item.append(element('span', `ID：${profile.id}　revision ${profile.active_revision}`));
                });
            } catch (error) { list.replaceChildren(element('p', error.message, 'error')); }
        }
        bindForm(form, apply, message, async data => {
            if (applyRunning || pendingOperation) throw new Error('請先完成目前的 Safe Apply 確認或回復。');
            const payload = { id_or_name: required(selected, 'Profile'), interface_id: required(data.interface_id, '目標介面'), confirm_timeout_seconds: integer(data.timeout, '確認期限', 10, 600) };
            if (!globalThis.confirm(`將 Profile「${selected}」套用到「${payload.interface_id}」？網路連線可能暫時中斷。`)) { report(message, '已取消套用。'); return; }
            applyRunning = true;
            try {
                await requestJson('/api/portable-helper', { method: 'POST' });
                const response = await requestAction('profile.apply', payload); output.textContent = JSON.stringify(response, null, 2);
                pendingOperation = safeApplyOperation(response); $('#operation-id').value = pendingOperation; $('#safe-apply').hidden = false;
                const deadline = response.data.deadline_unix_seconds;
                report($('#safe-status'), `已套用，等待確認。${deadline ? `Helper 期限：${new Date(deadline * 1000).toLocaleString('zh-TW')}。` : ''}請先檢查連線。`);
                report(message, '已套用，請使用頁面上方 Safe Apply 確認或回復。');
            } finally { applyRunning = false; }
        });
        const create = formCard(content, '建立 Profile', '預設為 IPv4 DHCP、IPv6 自動設定與自動 DNS。進階設定可修改完整 JSON，由 Agent 驗證。');
        const fields = element('div', undefined, 'form-grid'); create.form.append(fields);
        field(fields, 'id', 'Profile ID', '', { maxLength: 64, placeholder: 'office', id: 'profile-id' });
        field(fields, 'name', '顯示名稱', '', { maxLength: 128, id: 'profile-name' });
        field(create.form, 'configuration', '網路設定 JSON', JSON.stringify(defaultConfiguration, null, 2), { multiline: true, id: 'profile-configuration' });
        const save = button(create.form, '建立 Profile', null, true); save.type = 'submit'; const saveStatus = status(create.panel);
        bindForm(create.form, save, saveStatus, async data => {
            const configuration = JSON.parse(data.configuration);
            if (!configuration || typeof configuration !== 'object' || Array.isArray(configuration)) throw new Error('網路設定必須是 JSON object。');
            const id = required(data.id, 'Profile ID'); await requestAction('profile.create', { id, name: required(data.name, '顯示名稱'), configuration });
            report(saveStatus, 'Profile 已建立，尚未套用。'); create.form.reset(); create.form.elements.configuration.value = JSON.stringify(defaultConfiguration, null, 2);
            await load(); await show(id);
        }); load();
    }
    async function finishSafeApply(action) {
        const message = $('#safe-status'); if (safeBusy) return;
        safeBusy = true; $('#profile-confirm').disabled = true; $('#profile-rollback').disabled = true;
        try {
            const operation_id = required($('#operation-id').value, '操作識別碼'); report(message, '處理中…');
            const response = await requestAction(action, { operation_id });
            if (!safeApplyCompleted(action, response.data)) throw new Error(`Helper 尚未回報操作成功，請檢查 Helper；操作識別碼已保留。`);
            if (pendingOperation === operation_id) pendingOperation = '';
            $('#operation-id').value = ''; report(message, action === 'profile.confirm' ? '已確認保留設定。' : '已回復原設定。');
        } catch (error) { report(message, error.message, true); }
        finally { safeBusy = false; $('#profile-confirm').disabled = false; $('#profile-rollback').disabled = false; }
    }
    function history(parent = content) {
        const panel = card(parent, '最近測速紀錄');
        query(panel, 'speed.history', { limit: 20 }, data => table(panel, data, [['Session ID', 'session_id'], ['Node', 'remote_node'], ['協定', 'protocol'], ['Backend', 'backend'], ['方向', 'direction'], ['開始時間', 'started_at'], ['狀態', 'state']], '最近 20 筆測速', '尚無測速紀錄。請先配對 Node，再執行測速。'));
    }
    function speed() {
        const { panel, form } = formCard(content, '基本 socket 測速', '先在雙端完成 Node 配對，並在對端設定 NETTOOL_CONTROL_LISTEN。預熱與冷卻各 1 秒；測試會產生實際網路流量。');
        const grid = element('div', undefined, 'form-grid'); form.append(grid);
        field(grid, 'node', '對端 Node 名稱或 ID', '', { placeholder: 'lab-server' });
        const protocol = field(grid, 'protocol', '協定', 'tcp', { choices: [['tcp', 'TCP'], ['udp', 'UDP']] });
        field(grid, 'direction', '測試方向', 'upload', { choices: [['upload', '上傳'], ['download', '下載'], ['bidirectional', '雙向']] });
        field(grid, 'duration', '測量時間（秒）', '10', { type: 'number', min: 1, max: 3600 });
        field(grid, 'streams', '串流數', '1', { type: 'number', min: 1, max: 65535 });
        const rate = field(grid, 'rate', 'UDP 目標速率（Mbps）', '10', { type: 'number', min: 0.000001, step: 'any' });
        rate.disabled = true; protocol.addEventListener('change', () => { rate.disabled = protocol.value !== 'udp'; });
        const run = button(form, '開始測速', null, true); run.type = 'submit'; run.disabled = speedRunning;
        const message = status(panel), output = element('pre'); output.hidden = true; panel.append(output);
        bindForm(form, run, message, async data => {
            if (speedRunning) throw new Error('本頁測速仍在執行，請稍候或查詢歷史。');
            const payload = buildSpeedPayload(data); speedRunning = true; report(message, '測速中；切換頁面不會取消測試。');
            try {
                const response = await requestAction('speed.run', payload); output.hidden = false; output.textContent = JSON.stringify(response.data, null, 2);
                report(message, '測速已完成，可重新整理查看最新歷史。');
            } finally { speedRunning = false; }
        });
        card(content, '伺服器專用進階測試', 'DPDK、AF_XDP、RIO、raw Ethernet、NUMA 與高速 benchmark 請使用 CLI 或進階 Action Console。基本表單固定使用 socket，不會宣稱 100GbE 認證。'); history();
    }
    function packets() {
        const { panel, form } = formCard(content, 'PCAP／PCAPNG 離線分析', '輸入 Agent 主機上可讀取的完整路徑。本表單不會上傳檔案；間隔 1 表示完整分析，10 表示每 10 個封包取樣一次。');
        field(form, 'input', '封包檔案路徑', '', { placeholder: 'D:\\captures\\capture.pcapng' }); field(form, 'sample', '取樣間隔', '1', { type: 'number', min: 1, max: 4294967295 });
        const run = button(form, '分析檔案', null, true); run.type = 'submit'; const message = status(panel), result = element('div'); panel.append(result);
        bindForm(form, run, message, async data => {
            result.replaceChildren(); const response = await requestAction('packet.analyze', buildAnalyzePayload(data));
            report(message, response.data.analysis?.coverage === 'full' ? '完整分析完成。' : '取樣分析完成；統計僅涵蓋取樣封包。'); raw(result, response); result.querySelector('details').open = true;
        });
        const live = card(content, '目前連線（Linux）', '此查詢使用 Linux procfs；其他平台會回報不支援。離線分析仍可使用。'), liveResult = element('div');
        button(live, '查詢 TCP／UDP 連線', async event => {
            const trigger = event.currentTarget; trigger.disabled = true; liveResult.replaceChildren();
            await query(liveResult, 'packet.connections', {}, data => table(liveResult, data.connections || [], [['協定', 'protocol'], ['本機位址', 'local_address'], ['本機 Port', 'local_port'], ['遠端位址', 'remote_address'], ['遠端 Port', 'remote_port'], ['狀態', 'connection_state']], '目前連線')); trigger.disabled = false;
        }); live.append(liveResult);
    }
    function nodes() {
        const list = card(content, '可信任的 Node'), listResult = element('div'); list.append(listResult);
        async function load() {
            listResult.replaceChildren(); await query(listResult, 'node.status', {}, data => table(listResult, data.nodes || [], [['名稱', 'name'], ['Node ID', 'id'], ['控制位址', 'control_address'], ['TLS 名稱', 'server_name'], ['信任狀態', 'state']], '已完成配對的對端', '尚無可信任 Node，請在下方配對。'));
        }
        const { panel, form } = formCard(content, '配對 Node', '選取 DER 憑證並獨立核對 SPKI 指紋。憑證會經本機 GUI 轉交 Agent 驗證；請勿提供私鑰。');
        const grid = element('div', undefined, 'form-grid'); form.append(grid);
        field(grid, 'node_id', 'Node ID（32 位十六進位）', '', { maxLength: 32 }); field(grid, 'name', '顯示名稱');
        field(grid, 'control_address', '控制位址', '', { placeholder: '192.0.2.10:9443' }); field(grid, 'server_name', 'TLS server name'); field(grid, 'fingerprint', 'SPKI fingerprint');
        const certificate = field(grid, 'certificate', 'DER 憑證', '', { type: 'file', accept: '.der,.crt,application/octet-stream' });
        const checked = checkbox(form, 'fingerprint_confirmed', '我已透過獨立管道核對對端指紋。', true), replacement = checkbox(form, 'identity_change', '若此 Node ID 已存在且身分不同，我確認取代原本的信任身分。');
        const pair = button(form, '配對 Node', null, true); pair.type = 'submit'; const message = status(panel);
        bindForm(form, pair, message, async data => {
            if (!/^[0-9a-f]{32}$/i.test(data.node_id)) throw new Error('Node ID 必須是 32 位十六進位。');
            if (!checked.checked) throw new Error('請先獨立核對指紋。');
            const file = certificate.files[0]; if (!file || file.size > 8192) throw new Error('請選取不超過 8 KiB 的 DER 憑證。');
            await requestAction('node.pair', { node_id: data.node_id, name: required(data.name, '名稱'), control_address: required(data.control_address, '控制位址'), server_name: required(data.server_name, 'TLS server name'), fingerprint: required(data.fingerprint, '指紋'), certificate_der: Array.from(new Uint8Array(await file.arrayBuffer())), out_of_band_fingerprint_confirmed: true, identity_change_confirmed: replacement.checked });
            report(message, 'Node 已配對。'); form.reset(); await load();
        }); load();
    }
    function help() {
        const panel = card(content, '建議操作順序'), steps = element('ol');
        ['確認 Agent 正常；若無法連線，先執行 cargo run -p nettool-agent。', '到網路介面確認名稱與 IP，到環境與能力查看平台限制。', '建立 Profile，指定介面套用；檢查連線後使用 Safe Apply 確認或回復。', '測速前先在雙端配對並啟用對端控制監聽，再填寫測速參數。', '離線分析填寫 Agent 可讀取的封包路徑；取樣不能視為完整統計。'].forEach(text => steps.append(element('li', text))); panel.append(steps);
        const features = card(content, '功能與使用條件');
        table(features, [
            { name: '介面查詢、Profile 保存、離線分析', condition: '一般裝置可用；欄位完整度依作業系統而異。' },
            { name: 'Profile 套用、IP／DNS、Hosts', condition: '需要 Helper；進階操作使用 CLI／Action Console。' },
            { name: 'TCP／UDP 測速', condition: '需要雙端配對與可達的控制位址；會產生流量。' },
            { name: '即時連線／封包統計', condition: '目前限 Linux procfs／sysfs。' },
            { name: 'DPDK／AF_XDP／RIO／100GbE', condition: '伺服器專用；需要原生 backend 與實機驗證，不提供 100G Certified。' },
        ], [['功能', 'name'], ['條件與限制', 'condition']], '功能分析');
        card(content, '常見問題', 'Agent 未啟動：啟動後重新整理。Helper 未設定：安裝並設定 Helper。Node 未配對：核對指紋後配對。backend 未建置：檢查環境與建置選項。Safe Apply 逾期：以 Helper 狀態為準，GUI 不會自行宣稱回復成功。');
        const commands = card(content, '啟動與完整文件'); commands.append(element('pre', 'cargo run -p nettool-agent\ncargo run -p nettool-gui\n# 開啟 http://127.0.0.1:8765\n\n# 原生桌面入口\ncargo run -p nettool-desktop'));
        commands.append(element('p', '完整說明：docs/GUI_GUIDE.md；命令參考：docs/CLI_REFERENCE.md。', 'hint'));
    }
    function navigate(name) {
        if (!pages[name]) return;
        currentPage = name; $('#page').textContent = pages[name][0]; $('#page-hint').textContent = pages[name][1];
        document.querySelectorAll('nav button').forEach(node => { if (node.dataset.page === name) node.setAttribute('aria-current', 'page'); else node.removeAttribute('aria-current'); });
        content.replaceChildren(); $('#safe-apply').hidden = name !== 'profiles' && !pendingOperation && !applyRunning;
        const renderers = {
            dashboard, interfaces, profiles, speed, packets, nodes, history, help,
            hosts: () => { const panel = card(content, '目前 Hosts', '本頁唯讀；修改、啟停、備份與恢復使用 CLI 或 Action Console，需要 Helper。'); query(panel, 'hosts.read', {}, data => panel.append(element('pre', typeof data === 'string' ? data : JSON.stringify(data, null, 2)))); },
            settings: () => { const panel = card(content, '唯讀環境探測', '分別檢查 capability、implementation 與 runtime gate；找到 SDK 不等於 backend 可用。'); query(panel, 'dataplane.probe', {}, data => { raw(panel, data, '平台與 NIC 探測報告'); panel.querySelector('details').open = true; }); },
        }; renderers[name]();
    }
    function actionScope() {
        const item = actionMetadata.get($('#action-select').value);
        $('#action-scope').textContent = item ? `${item.server_only ? '【伺服器專用】需要原生 backend 與相容硬體。' : '一般裝置可用，仍受平台與權限限制。'} 權限：${item.permission}。命令：${item.cli}` : '尚未載入 Action 清單。';
    }
    async function loadActions() {
        const run = $('#run-action'); run.disabled = true;
        try {
            const actions = await requestJson('/api/actions'); if (!Array.isArray(actions)) throw new Error('Action 清單格式無效。');
            $('#action-select').replaceChildren(); actionMetadata.clear();
            actions.forEach(item => { actionMetadata.set(item.name, item); const option = element('option', `${item.server_only ? '【伺服器專用】' : ''}${item.name}`); option.value = item.name; $('#action-select').append(option); }); actionScope(); run.disabled = actions.length === 0;
        } catch (error) { $('#action-scope').textContent = error.message; }
    }
    document.querySelectorAll('nav button').forEach(node => node.addEventListener('click', () => navigate(node.dataset.page)));
    $('#refresh').addEventListener('click', () => { navigate(currentPage); if (!actionMetadata.size) loadActions(); });
    $('#profile-confirm').addEventListener('click', () => finishSafeApply('profile.confirm'));
    $('#profile-rollback').addEventListener('click', () => finishSafeApply('profile.rollback'));
    $('#action-select').addEventListener('change', actionScope);
    $('#run-action').addEventListener('click', async event => {
        const run = event.currentTarget, output = $('#action-result'); run.disabled = true; output.textContent = '處理中…';
        try {
            const action = $('#action-select').value, descriptor = actionMetadata.get(action); if (!descriptor) throw new Error('請選取有效 Action。');
            const payload = JSON.parse($('#action-payload').value); if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('參數必須是 JSON object。');
            if (['profile.apply', 'ip.set', 'ip.dhcp', 'dns.set'].includes(action) && (pendingOperation || applyRunning)) throw new Error('請先完成目前的 Safe Apply 確認或回復。');
            if (descriptor.permission !== 'ReadOnly' && !globalThis.confirm(`確定執行 ${action}？請核對參數與影響。`)) { output.textContent = '已取消操作。'; return; }
            const response = await requestAction(action, payload); output.textContent = JSON.stringify(response, null, 2);
            if (['profile.apply', 'ip.set', 'ip.dhcp', 'dns.set'].includes(action)) {
                pendingOperation = safeApplyOperation(response); $('#operation-id').value = pendingOperation; $('#safe-apply').hidden = false; report($('#safe-status'), '已套用，請檢查連線並在 Helper 期限內確認或回復。');
            }
        } catch (error) { output.textContent = error.message; }
        finally { run.disabled = false; }
    }); loadActions(); navigate('dashboard');
}());
