const content = document.querySelector('#content'), page = document.querySelector('#page'), actionMetadata = new Map(); let selectedProfileId='';
const payloads = { Dashboard:['system.health',{}], 'Network Interfaces':['interface.list',{}], Profiles:['profile.list',{}], Hosts:['hosts.read',{}], 'Speed history':['speed.history',{limit:20}], 'Packet connections':['packet.connections',{}], Node:['node.status',{}], Environment:['dataplane.probe',{}] };
const csrfToken = document.querySelector('meta[name="nettool-csrf"]').content;
async function post(path, body) {
    const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-NetTool-CSRF': csrfToken },
        body: JSON.stringify(body)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error?.message || 'GUI request failed');
    return result;
}
async function call(action, payload, operationId) {
    return post('/api/action', { action, payload, ...(operationId ? { operation_id: operationId } : {}) });
}
function renderActionScope(){ const item=actionMetadata.get(document.querySelector('#action-select').value), scope=document.querySelector('#action-scope'); scope.textContent=item?.server_only?'【伺服器專用】需要長時間測試或高速 NIC、NUMA、Huge Page、native backend；一般筆電可查詢，但不適合作為效能驗收。':'一般裝置可用；實際可用能力仍依作業系統、權限與硬體而定。'; }
async function loadActions(){ const actions=await (await fetch('/api/actions')).json(); const select=document.querySelector('#action-select'); actions.forEach(item=>{ actionMetadata.set(item.name,item); const option=document.createElement('option'); option.value=item.name; option.textContent=(item.server_only?'【伺服器專用】 ':'')+item.name+' — '+item.cli; select.appendChild(option); }); renderActionScope(); }
function showResult(container, title, result) {
    const heading = document.createElement('h3'), output = document.createElement('pre');
    heading.textContent = title;
    output.textContent = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
    container.replaceChildren(heading, output);
}
let renderGeneration = 0;
async function render(name) {
    const generation = ++renderGeneration;
    page.textContent = name;
    if (name === 'Profiles') { renderProfilesPage(); return; }
    if (name === 'Node') { renderNodePage(); return; }
    const entry = payloads[name];
    if (!entry) { showResult(content, 'Unknown page', name); return; }
    showResult(content, name, 'Loading…');
    try {
        const result = await call(...entry);
        if (generation === renderGeneration) showResult(content, name, result);
    } catch (error) {
        if (generation === renderGeneration) showResult(content, 'Agent unavailable', String(error));
    }
}
const defaultProfileConfiguration = JSON.stringify({ipv4:{mode:'dhcp'},ipv6:{mode:'automatic'},dns:{automatic:true,servers:[],search_domains:[]},routes:[],mtu:null},null,2);
function renderProfilesPage(){ selectedProfileId=''; content.innerHTML='<div class="profile-layout"><section class="card"><div class="toolbar" style="margin-bottom:12px"><h3>Saved profiles</h3><button class="secondary" id="profile-reload" type="button">Reload</button></div><p class="hint">選取 profile 可讀取目前保存的完整設定。</p><div id="profile-list" class="profile-list" aria-live="polite"></div></section><section class="card"><h3 id="profile-detail-title">Profile details</h3><p class="hint">套用會使用 Safe Apply；一般免安裝版會明確要求安裝 Helper。</p><pre id="profile-detail" class="profile-detail">請從左側選取 profile。</pre><div class="form-actions"><label for="profile-interface" class="hint">Interface ID<input id="profile-interface" autocomplete="off" placeholder="Ethernet"></label><label for="profile-timeout" class="hint">Confirm seconds<input id="profile-timeout" type="number" min="10" max="600" value="60"></label><button class="primary" id="profile-apply" type="button" disabled>Apply profile</button></div><p id="profile-apply-status" class="status" role="status" aria-live="polite"></p></section></div><section class="card" style="margin-top:14px"><h3>Create profile</h3><p class="hint">設定會由 Agent 驗證並保存為 revision 1。請使用完整 IPv4、IPv6、DNS、routes、MTU schema。</p><form id="profile-create-form" class="profile-form"><div class="form-grid"><label for="profile-id">Profile ID<input id="profile-id" name="id" autocomplete="off" required maxlength="64" aria-describedby="profile-id-help"></label><label for="profile-name">Display name<input id="profile-name" name="name" autocomplete="off" required maxlength="128"></label></div><p id="profile-id-help" class="hint">使用穩定、好辨識的 ID，例如 office 或 lab-dhcp。</p><label for="profile-configuration">Network configuration JSON<textarea id="profile-configuration" name="configuration" spellcheck="false" required aria-describedby="profile-configuration-help"></textarea></label><p id="profile-configuration-help" class="hint">可從 DHCP 範本開始，或改成 static addresses、DNS 與 routes。</p><div class="form-actions"><button class="primary" id="profile-create-submit" type="submit">Create profile</button><span id="profile-create-status" class="status" role="status" aria-live="polite"></span></div><pre id="profile-create-result" hidden></pre></form></section>'; document.querySelector('#profile-configuration').value=defaultProfileConfiguration; document.querySelector('#profile-reload').addEventListener('click',loadProfiles); document.querySelector('#profile-create-form').addEventListener('submit',createProfile); document.querySelector('#profile-apply').addEventListener('click',applySelectedProfile); loadProfiles(); updateSafeApply(); }
async function loadProfiles(){ const list=document.querySelector('#profile-list'); if(!list) return; list.replaceChildren(); const loading=document.createElement('p'); loading.className='hint'; loading.textContent='Loading profiles…'; list.appendChild(loading); try { const response=await call('profile.list',{}); if(!response.success) throw new Error(response.error?.message||'profile list failed'); const profiles=response.data; if(!Array.isArray(profiles)||profiles.length===0){ loading.textContent='尚未建立 profile。'; return; } list.replaceChildren(); profiles.forEach(summary=>{ const item=document.createElement('button'); item.type='button'; item.className='profile-item'; item.setAttribute('aria-label','Read profile '+String(summary.name||summary.id||'')); const title=document.createElement('strong'); title.textContent=String(summary.name||summary.id||'Unnamed profile'); const meta=document.createElement('span'); meta.textContent='ID: '+String(summary.id||'')+' · revision '+String(summary.active_revision??'?'); item.append(title,meta); item.addEventListener('click',()=>showProfile(String(summary.id))); list.appendChild(item); }); } catch(error){ list.replaceChildren(loading); loading.textContent='Unable to load profiles: '+String(error); } }
async function showProfile(id){ const title=document.querySelector('#profile-detail-title'), output=document.querySelector('#profile-detail'), apply=document.querySelector('#profile-apply'); if(!title||!output) return; selectedProfileId=id; title.textContent='Profile details — '+id; output.textContent='Loading…'; if(apply) updateSafeApply(); try { const response=await call('profile.show',{id_or_name:id}); output.textContent=JSON.stringify(response,null,2); } catch(error){ output.textContent='Unable to read profile: '+String(error); } }
const pendingKey = 'nettool.pending-safe-apply';
let pendingApply = null, safeApplyBusy = false, applyBusy = false;
const safeApplyPanel = document.querySelector('#safe-apply-panel');
const safeApplyStatus = document.querySelector('#safe-apply-status');
const safeApplyNotice = document.querySelector('#safe-apply-notice');

function savePending(record) {
    // 在送出變更前保存 operation ID；重新整理後仍可要求同一筆 rollback。
    sessionStorage.setItem(pendingKey, JSON.stringify(record));
    pendingApply = record;
    updateSafeApply();
}
function restorePending() {
    try {
        const saved = JSON.parse(sessionStorage.getItem(pendingKey) || 'null');
        if (saved && typeof saved.operation_id === 'string'
            && /^[A-Za-z0-9_-]{1,128}$/.test(saved.operation_id)
            && Number.isSafeInteger(saved.deadline_unix_seconds)
            && typeof saved.target_interface === 'string') pendingApply = saved;
    } catch (error) { safeApplyNotice.textContent = '無法讀取待確認操作：' + String(error); }
    updateSafeApply();
}
function updateSafeApply() {
    safeApplyPanel.hidden = !pendingApply;
    const apply = document.querySelector('#profile-apply');
    if (apply) apply.disabled = applyBusy || !!pendingApply || !selectedProfileId;
    if (!pendingApply) return;
    const remaining = Math.max(0, Math.ceil(pendingApply.deadline_unix_seconds - Date.now() / 1000));
    const confirmedApply = pendingApply.state === 'pending_confirmation';
    safeApplyStatus.textContent = '介面 ' + pendingApply.target_interface + ' · 操作 ' + pendingApply.operation_id
        + (remaining > 0
            ? (confirmedApply ? ' · 請確認連線正常，剩餘 ' + remaining + ' 秒。' : ' · 套用結果尚未確認，可要求回復；預估剩餘 ' + remaining + ' 秒。')
            : ' · 確認期限已過，Helper 應自動回復；尚未取得回復完成證據。');
    document.querySelector('#safe-apply-confirm').disabled = safeApplyBusy || applyBusy || !confirmedApply || remaining === 0;
    document.querySelector('#safe-apply-rollback').disabled = safeApplyBusy || applyBusy;
    document.querySelector('#safe-apply-dismiss').hidden = remaining > 0;
    document.querySelector('#safe-apply-dismiss').disabled = safeApplyBusy || applyBusy;
}
async function finishSafeApply(action) {
    if (!pendingApply || safeApplyBusy || applyBusy) return;
    const record = pendingApply;
    if (action === 'profile.confirm'
        && (record.state !== 'pending_confirmation' || Date.now() / 1000 >= record.deadline_unix_seconds)) return;
    safeApplyBusy = true;
    safeApplyNotice.textContent = action === 'profile.confirm' ? '正在確認…' : '正在要求回復…';
    updateSafeApply();
    try {
        const response = await call(action, { operation_id: record.operation_id });
        if (!response.success) throw new Error(response.error?.message || 'Safe Apply request failed');
        const completed = action === 'profile.confirm'
            ? response.data?.state === 'confirmed' && response.data?.operation_id === record.operation_id
            : response.data?.rolled_back === true;
        if (!completed) throw new Error('Helper 未回傳預期的完成狀態');
        sessionStorage.removeItem(pendingKey);
        pendingApply = null;
        safeApplyNotice.textContent = action === 'profile.confirm' ? '已確認，保留目前網路設定。' : 'Helper 已完成回復。';
    } catch (error) {
        safeApplyNotice.textContent = '操作結果尚未確認：' + String(error) + '。保留 operation ID，可再次查核或要求回復。';
    } finally { safeApplyBusy = false; updateSafeApply(); }
}
async function applySelectedProfile() {
    const status = document.querySelector('#profile-apply-status');
    const interfaceId = document.querySelector('#profile-interface').value.trim();
    const timeout = Number(document.querySelector('#profile-timeout').value);
    if (applyBusy || pendingApply) return;
    if (!selectedProfileId || !interfaceId) { status.textContent = '請先選擇 profile 並填寫 Interface ID。'; return; }
    if (!Number.isInteger(timeout) || timeout < 10 || timeout > 600) { status.textContent = '確認時間必須介於 10 至 600 秒。'; return; }
    const profileId = selectedProfileId;
    applyBusy = true;
    updateSafeApply();
    try {
        status.textContent = '正在準備 Helper…';
        const helper = await post('/api/portable-helper', {});
        if (!helper.success) throw new Error(helper.error?.message || 'Helper is required');
        const record = {
            operation_id: 'gui-' + crypto.randomUUID(),
            target_interface: interfaceId,
            deadline_unix_seconds: Math.floor(Date.now() / 1000) + timeout,
            state: 'unknown'
        };
        savePending(record);
        safeApplyNotice.textContent = '';
        status.textContent = '正在套用；請稍候…';
        // UAC Helper 可能尚未就緒；重試固定沿用同一 operation ID，避免重複套用。
        let response;
        for (let attempt = 0; attempt < 10; attempt += 1) {
            response = await call('profile.apply', {
                id_or_name: profileId, interface_id: interfaceId, confirm_timeout_seconds: timeout
            }, record.operation_id);
            if (response.success || response.error?.code !== 'HELPER.TRANSPORT_FAILED'
                || !response.error?.retryable || attempt === 9) break;
            await new Promise(resolve => setTimeout(resolve, 250));
        }
        if (!response.success) throw new Error(response.error?.message || 'profile apply failed');
        const result = response.data;
        if (result?.operation_id !== record.operation_id || result.state !== 'pending_confirmation'
            || !Number.isSafeInteger(result.deadline_unix_seconds)) throw new Error('Helper 未回傳有效的確認期限');
        savePending({ ...record, state: result.state, deadline_unix_seconds: result.deadline_unix_seconds });
        status.textContent = 'Profile 已套用，請使用上方按鈕確認或回復。';
        const output = document.querySelector('#profile-detail');
        if (output) output.textContent = JSON.stringify(response, null, 2);
    } catch (error) {
        status.textContent = pendingApply ? '套用結果尚未確認：' + String(error) : '未套用 profile：' + String(error);
        safeApplyNotice.textContent = status.textContent;
    } finally { applyBusy = false; updateSafeApply(); }
}
async function createProfile(event){ event.preventDefault(); const form=event.currentTarget, id=form.elements.id.value.trim(), name=form.elements.name.value.trim(), configurationText=form.elements.configuration.value, button=document.querySelector('#profile-create-submit'), status=document.querySelector('#profile-create-status'), output=document.querySelector('#profile-create-result'); output.hidden=false; try { if(!id||!name) throw new Error('Profile ID and display name are required'); const configuration=JSON.parse(configurationText); if(!configuration||Array.isArray(configuration)||typeof configuration!=='object') throw new Error('Network configuration must be a JSON object'); button.disabled=true; status.textContent='Saving profile…'; const response=await call('profile.create',{id,name,configuration}); output.textContent=JSON.stringify(response,null,2); if(!response.success) throw new Error(response.error?.message||'profile create failed'); status.textContent='Profile saved.'; form.reset(); form.elements.configuration.value=defaultProfileConfiguration; await loadProfiles(); await showProfile(id); } catch(error){ status.textContent='Profile was not saved.'; output.textContent=String(error); } finally { button.disabled=false; } }
function renderNodePage(){ content.innerHTML='<div class="card"><h3>Trusted Node pairing</h3><p class="hint">配對資料會經 Agent 的 typed Action API 保存；certificate 會在瀏覽器轉成 DER bytes，經本機 GUI 轉交 Agent 驗證。</p><div class="form-grid"><label>Node ID (32 hex)<input id="pair-node-id" maxlength="32" autocomplete="off"></label><label>Name<input id="pair-name" autocomplete="off"></label><label>Control address<input id="pair-address" placeholder="192.0.2.10:9443" autocomplete="off"></label><label>TLS server name<input id="pair-server" autocomplete="off"></label><label>SPKI fingerprint<input id="pair-fingerprint" autocomplete="off"></label><label>Certificate DER<input id="pair-certificate" type="file" accept=".der,.crt,application/octet-stream"></label></div><label class="hint" style="display:block;margin:12px 0"><input id="pair-fingerprint-confirm" type="checkbox"> I verified this fingerprint through an independent out-of-band channel</label><label class="hint" style="display:block;margin:12px 0"><input id="pair-confirm" type="checkbox"> Confirm identity replacement if an existing Node identity differs</label><button class="primary" id="pair-submit">Pair Node</button><pre id="pair-result" style="max-height:180px">尚未執行配對。</pre></div><div class="card" style="margin-top:14px"><h3>Current trusted Nodes</h3><p class="hint">Loading…</p></div>'; document.querySelector('#pair-submit').addEventListener('click',pairNode); loadNodeStatus(); }
async function loadNodeStatus() {
    const card = content.querySelectorAll('.card')[1];
    try { showResult(card, 'Current trusted Nodes', await call('node.status', {})); }
    catch (error) { showResult(card, 'Agent unavailable', String(error)); }
}
async function pairNode(){ const output=document.querySelector('#pair-result'); try { const file=document.querySelector('#pair-certificate').files[0]; if(!file) throw new Error('certificate DER file is required'); if(!document.querySelector('#pair-fingerprint-confirm').checked) throw new Error('out-of-band fingerprint verification is required'); const bytes=Array.from(new Uint8Array(await file.arrayBuffer())); const payload={node_id:document.querySelector('#pair-node-id').value.trim(),name:document.querySelector('#pair-name').value.trim(),control_address:document.querySelector('#pair-address').value.trim(),server_name:document.querySelector('#pair-server').value.trim(),fingerprint:document.querySelector('#pair-fingerprint').value.trim(),certificate_der:bytes,out_of_band_fingerprint_confirmed:true,identity_change_confirmed:document.querySelector('#pair-confirm').checked}; output.textContent=JSON.stringify(await call('node.pair',payload),null,2); loadNodeStatus(); } catch(error) { output.textContent=String(error); } }
document.querySelectorAll('nav button').forEach(button=>button.addEventListener('click',()=>{document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));button.classList.add('active');render(button.dataset.page);})); document.querySelector('#refresh').addEventListener('click',()=>render(page.textContent)); document.querySelector('#action-select').addEventListener('change',renderActionScope); document.querySelector('#run-action').addEventListener('click',async()=>{const output=document.querySelector('#action-result'); try { const payload=JSON.parse(document.querySelector('#action-payload').value); output.textContent=JSON.stringify(await call(document.querySelector('#action-select').value,payload),null,2); } catch(error) { output.textContent=String(error); }}); loadActions().catch(error => { document.querySelector('#action-scope').textContent = '無法載入 actions：' + String(error); }); render('Dashboard');

document.querySelector('#safe-apply-confirm').addEventListener('click', () => finishSafeApply('profile.confirm'));
document.querySelector('#safe-apply-rollback').addEventListener('click', () => finishSafeApply('profile.rollback'));
document.querySelector('#safe-apply-dismiss').addEventListener('click', () => {
    if (!pendingApply || applyBusy || safeApplyBusy || Date.now() / 1000 < pendingApply.deadline_unix_seconds) return;
    if (!window.confirm('這只會清除本頁提示，不表示網路已回復。請先確認介面狀態，是否繼續？')) return;
    try {
        sessionStorage.removeItem(pendingKey);
        pendingApply = null;
        safeApplyNotice.textContent = '已清除提示；請以介面狀態確認實際設定。';
        updateSafeApply();
    } catch (error) { safeApplyNotice.textContent = '無法清除提示：' + String(error); }
});
restorePending();
setInterval(updateSafeApply, 1000);
