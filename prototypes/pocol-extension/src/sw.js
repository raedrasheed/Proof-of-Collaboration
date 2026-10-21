// PoCol extension service worker: network profiles, verified site loading
// (RP window or LN trust), BridgeAuth for site messages, DNR isolation, wallet.
import { decodeSpec, verifyWindow } from './lib/rp.js';
import { fetchSite, normalize } from './lib/site.js';
import * as bridge from './lib/bridge.js';
import { StoreAdmission, qbytes } from './lib/sitestore.js';
import { RecordStore } from './lib/records.js';
import * as http from './lib/transport.js';
import { encryptSeed, decryptSeed, networkKey, addressOf, signTx, LOCK_MS } from './lib/wallet.js';
import { keccak } from './lib/crypto.js';
import * as rlp from './lib/rlp.js';
import { toHex, fromHex, eq } from './lib/hex.js';

const store = chrome.storage.local;
// Site storage records with a worker-generation fence (D103); no data write before the fence confirms.
const records = new RecordStore(store);
const booted = records.boot().catch(() => null);
const genId = crypto.randomUUID();
const admission = new StoreAdmission();
const sessions = new Map(); // sessionId -> SiteSession (D99)
let globalPending = 0;
let unlocked = null; // {seed, until}
const RPC_TIMEOUT_MS = 10000, LOGS_TIMEOUT_MS = 30000, LOG_RANGE_MAX = 1024;
const WALLET_PER_MIN = 5;

// ---------------- profiles ----------------
export function netKeyOf(chainId, genesisHash) {
  return toHex(keccak(rlp.encode([new TextEncoder().encode('PoCol-net-v1'), rlp.encUint(BigInt(chainId)), genesisHash])));
}
async function profiles() { return (await store.get('profiles')).profiles || []; }
/** Profile acceptance (browser.md D58/D77/D79): decode genesisPre, hash, chainId. */
function validateProfile(p) {
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(p.name)) throw new Error('name');
  if (!['DEV', 'LN', 'RP'].includes(p.trustLevel)) throw new Error('trustLevel');
  if (!/^http:\/\/127\.0\.0\.1:\d{1,5}\/?$/.test(p.endpoint)) throw new Error('endpoint must be http://127.0.0.1:<port> (optional remote hosts are not enabled)');
  const pre = fromHex(p.genesisPre); const spec = decodeSpec(pre);
  if (!eq(spec.genesisHash, fromHex(p.genesisHash))) throw new Error('genesisHash mismatch');
  if (spec.chainId !== BigInt(p.chainId)) throw new Error('chainId mismatch');
  return { name: p.name, chainId: Number(p.chainId), genesisPre: p.genesisPre, genesisHash: p.genesisHash.toLowerCase(), endpoint: p.endpoint, trustLevel: p.trustLevel, netKey: netKeyOf(p.chainId, spec.genesisHash) };
}
// HttpTransport pools (D98): trust checks never starve behind sites; chunk fetches have their own pool.
const pools = { site: new http.Pool(http.SITE_POOL), trust: new http.Pool(http.TRUST_POOL), content: new http.Pool(http.CONTENT_POOL) };
let reqId = 0;
/** rpc for one pool; session (optional) carries the per-session SESSION_RECV_MAX account. */
function rpcFor(profile, pool, session = null, shared = http.inflight) {
  return (method, params, timeoutMs = RPC_TIMEOUT_MS) => http.request(profile.endpoint, method, params, { pool, session, deadline: timeoutMs, id: ++reqId, shared: pool === pools.trust ? null : shared });
}
const contentRpc = (profile) => { const c = rpcFor(profile, pools.content), s = rpcFor(profile, pools.site); return (m, p) => (m === 'eth_getCode' ? c(m, p) : s(m, p)); };
/** netKey check against the endpoint: chainId and genesisHash must equal the profile. */
async function checkNetwork(profile, rpc) {
  const cid = BigInt(await rpc('eth_chainId', []));
  if (cid !== BigInt(profile.chainId)) throw Object.assign(new Error('endpoint chainId differs from profile'), { code: 4901 });
  const st = await rpc('pocol_status', []);
  if (st.genesisHash.toLowerCase() !== profile.genesisHash.toLowerCase()) throw Object.assign(new Error('endpoint genesis differs from profile'), { code: 4901 });
}

// ---------------- DNR isolation (layer 2) ----------------
// Rule ids (amendment LP9-DNR-01): browser.md names {2·tabId, 2·tabId+1}; Chrome tab ids can
// exceed 2^30, so ids come from a per-tab slot k (block 2k prio 1, allow 2k+1 prio 2). The
// condition still names the tab. The slot map is rebuilt from getSessionRules() after a
// worker restart. main_frame is not blocked: the sandboxed frame cannot navigate the top.
const SUB_TYPES = ['sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'];
let dnrChain = Promise.resolve();
const dnrLocked = (f) => { const r = dnrChain.then(f); dnrChain = r.catch(() => {}); return r; };
const tabRules = (rules, tabId) => rules.filter((r) => r.condition && Array.isArray(r.condition.tabIds) && r.condition.tabIds.length === 1 && r.condition.tabIds[0] === tabId);
function installDnr(tabId) {
  return dnrLocked(async () => {
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    const old = tabRules(rules, tabId).map((r) => r.id); const used = new Set(rules.map((r) => r.id));
    let k = 1; while (used.has(2 * k) || used.has(2 * k + 1)) k++;
    const block = 2 * k, allow = 2 * k + 1;
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: old,
      addRules: [
        { id: block, priority: 1, action: { type: 'block' }, condition: { tabIds: [tabId], resourceTypes: SUB_TYPES } },
        { id: allow, priority: 2, action: { type: 'allow' }, condition: { tabIds: [tabId], urlFilter: '|chrome-extension://' + chrome.runtime.id + '/', resourceTypes: SUB_TYPES } },
      ],
    });
    const now = tabRules(await chrome.declarativeNetRequest.getSessionRules(), tabId);
    if (!now.some((r) => r.id === block && r.action.type === 'block') || !now.some((r) => r.id === allow && r.action.type === 'allow')) throw Object.assign(new Error('DNR install failed (closed)'), { code: 4900 });
    return { block, allow };
  });
}
const opening = new Map(); // tabId -> opens in progress
function removeDnr(tabId) {
  return dnrLocked(async () => {
    if ((opening.get(tabId) || 0) > 0 || [...sessions.values()].some((s) => s.tabId === tabId)) return;
    const ids = tabRules(await chrome.declarativeNetRequest.getSessionRules(), tabId).map((r) => r.id);
    if (ids.length) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids });
  });
}
chrome.tabs.onRemoved.addListener((tabId) => { removeDnr(tabId).catch(() => {}); });

// ---------------- open a site (D26 step 2: the worker fetches and verifies) ----------------
const b64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000)); return btoa(s); };
async function openSite({ name, site, path, tabId }) {
  const profile = (await profiles()).find((p) => p.name === name); if (!profile) throw new Error('unknown profile ' + name);
  if (!/^0x[0-9a-fA-F]{40}$/.test(site)) throw new Error('site address');
  if (tabId === undefined) throw Object.assign(new Error('a site opens only in a viewer tab'), { code: 4900 });
  opening.set(tabId, (opening.get(tabId) || 0) + 1);
  try { return await openVerified(profile, site, path, tabId); } finally { opening.set(tabId, opening.get(tabId) - 1); if (!opening.get(tabId)) opening.delete(tabId); }
}
async function openVerified(profile, site, path, tabId) {
  /*@fault noDnr*/await installDnr(tabId);/*@else*//* TEST FAULT: DNR not installed *//*@end*/
  const rpc = rpcFor(profile, pools.trust); await checkNetwork(profile, rpc);
  let trust = { level: profile.trustLevel, message: profile.trustLevel === 'LN' ? 'LN: عقدة محلية تتحقق من التنفيذ كاملًا' : 'DEV: شبكة تطوير بلا تحقق' };
  if (profile.trustLevel === 'RP') {
    const spec = decodeSpec(fromHex(profile.genesisPre));
    try { trust = { level: 'RP', ...(await verifyWindow(rpc, spec)) }; }
    catch (e) { return { ok: false, error: { code: 4901, message: 'RP window rejected: ' + (e.flag || e.message) } }; }
    if (!trust.ok) return { ok: false, error: { code: 4901, message: trust.message } };
  }
  const s = await fetchSite(contentRpc(profile), site);
  const files = {}; for (const [p, f] of s.files) files[p] = { mime: f.mime, b64: b64(f.data) };
  const sessionId = crypto.randomUUID(); const now = Math.floor(performance.now());
  const recv = { recv: 0 };
  sessions.set(sessionId, { profile, site: site.toLowerCase(), netKey: profile.netKey, bucket: bridge.newSession(now), approved: false, rpc: rpcFor(profile, pools.site, recv), tabId,
    confirmPending: false, walletPending: false, walletTimes: [], storeQ: admission.session() });
  await booted; const snap = await records.load(profile.netKey, site); const storage = snap.dict;
  const norm = normalize(path || '/'); const target = norm === '' ? s.entry : norm;
  return { ok: true, sessionId, version: s.version, publishedBlock: s.publishedBlock, entry: s.entry, path: target, notFound: norm === null || !s.files.has(target), files, storage, storageError: snap.error || null, trust, netKey: profile.netKey };
}

// ---------------- B4 routing (state limits of the target component, D97) ----------------
const E = (code, message, data) => ({ error: data === undefined ? { code, message } : { code, message, data } });
/** Remote error objects pass through (already clipped by RecvGuard); local failures have fixed shapes. */
function transportError(e) {
  if (e.rpc) return { error: e.rpc };
  if (e.transport === 'busy') return E(-32005, 'busy', { reason: 'busy' });
  const reason = ['recvLimit', 'recvDepth', 'recvParse'].includes(e.transport) ? e.transport : 'transport';
  return E(-32603, reason, { reason });
}
async function rpcRead(sess, m) {
  // RpcReadClient re-checks the read allowlist independently of BridgeAuth B2 (defense in depth).
  /*@fault allowAll*/if (!bridge.ALLOW.get('rpc_read').has(m.method)) return E(4200, 'unsupported method', { method: m.method.slice(0, 64) });/*@else*//*@end*/
  if (sess.bucket.pendingReads >= bridge.PENDING_READS_MAX || globalPending >= bridge.GLOBAL_PENDING_READS_MAX) return E(-32005, 'pending', { reason: 'pending' });
  sess.bucket.pendingReads++; globalPending++;
  try {
    if (m.method === 'eth_getLogs') return await logClient(sess, m.params[0]);
    return { result: await sess.rpc(m.method, m.params) };
  } catch (e) { return transportError(e); }
  finally { sess.bucket.pendingReads--; globalPending--; }
}
/** LogClient.fetchAll: resolves tags, enforces the 1024-block range locally, then pocol_getLogs (never raw eth_getLogs). */
async function logClient(sess, f) {
  if (f.blockHash !== undefined) return { result: await sess.rpc('pocol_getLogs', [f], LOGS_TIMEOUT_MS) };
  const num = async (tag) => (tag.startsWith('0x') ? BigInt(tag) : BigInt((await sess.rpc('eth_getBlockByNumber', [tag, false])).number));
  const from = await num(f.fromBlock), to = await num(f.toBlock);
  if (to < from || to - from + 1n > BigInt(LOG_RANGE_MAX)) return E(-32020, 'range', { reason: 'range', limit: LOG_RANGE_MAX });
  return { result: await sess.rpc('pocol_getLogs', [{ ...f, fromBlock: '0x' + from.toString(16), toBlock: '0x' + to.toString(16) }], LOGS_TIMEOUT_MS) };
}
async function route(sess, m, ctl) {
  if (m.kind === 'rpc_read') return rpcRead(sess, m);
  if (m.kind === 'storage_set') {
    const q = qbytes(m.method, m.params);
    if (!admission.admit(sess.storeQ, q)) return E(-32005, 'store', { reason: 'store' });
    try { await booted; return await records.write(sess.netKey, sess.site, m.method, m.params); } finally { admission.release(sess.storeQ, q); }
  }
  if (m.kind === 'nav') {
    if (m.method === 'site_navigate') {
      if (!bridge.navTake(sess.bucket, ctl.arrivalMs)) return E(-32005, 'nav', { reason: 'nav' });
      const n = normalize(m.params[0]);
      ctl.navigate(n === null ? { notFound: true, path: m.params[0] } : { path: n });
      return { suppressed: true }; // no reply to the torn-down frame
    }
    if (sess.confirmPending) return E(-32005, 'pending', { reason: 'pending' });
    sess.confirmPending = true;
    try {
      const okExt = await ctl.ask({ type: 'confirmExternal', url: m.params[0] });
      if (!okExt) return E(4001, 'user rejected');
      await chrome.tabs.create({ url: m.params[0] }); return { result: null };
    } finally { sess.confirmPending = false; }
  }
  if (m.kind === 'wallet_req') {
    if (sess.walletPending) return E(-32005, 'pending', { reason: 'pending' });
    const now = Date.now(); sess.walletTimes = sess.walletTimes.filter((t) => now - t < 60000);
    if (sess.walletTimes.length >= WALLET_PER_MIN) return E(-32005, 'rate', { reason: 'wallet' });
    sess.walletTimes.push(now); sess.walletPending = true;
    try { return await wallet(sess, m, ctl.ask); } finally { sess.walletPending = false; }
  }
  return E(-32600, 'kind');
}
async function walletKey(sess) {
  if (!unlocked || Date.now() > unlocked.until) { unlocked = null; return null; }
  unlocked.until = Date.now() + LOCK_MS; return networkKey(unlocked.seed, sess.netKey);
}
async function wallet(sess, m, ask) {
  if (m.method === 'eth_chainId') return { result: '0x' + sess.profile.chainId.toString(16) };
  const key = await walletKey(sess);
  if (!key) return E(4100, 'wallet locked');
  const address = addressOf(key);
  if (m.method === 'eth_accounts') return { result: sess.approved ? [address] : [] };
  if (m.method === 'eth_requestAccounts') {
    if (!sess.approved) { const ok = await ask({ type: 'confirmAccounts', site: sess.site, address, network: sess.profile.name }); if (!ok) return E(4001, 'user rejected'); sess.approved = true; }
    return { result: [address] };
  }
  // eth_sendTransaction: build, show the exact bytes and hash bound to the network, sign only after approval, submit (WalletSubmit).
  if (!sess.approved) return E(4100, 'unauthorized');
  const o = m.params[0]; if (o.from && o.from.toLowerCase() !== address.toLowerCase()) return E(4100, 'from is not the granted account');
  try {
    const nonce = o.nonce ? BigInt(o.nonce) : BigInt(await sess.rpc('eth_getTransactionCount', [address, 'pending']));
    const base = BigInt((await sess.rpc('eth_getBlockByNumber', ['latest', false])).baseFeePerGas);
    const data = o.data || '0x', value = o.value ? BigInt(o.value) : 0n;
    const gas = o.gas ? BigInt(o.gas) : BigInt(await sess.rpc('eth_estimateGas', [{ from: address, to: o.to, data, value: '0x' + value.toString(16) }]));
    const maxPriority = o.maxPriorityFeePerGas ? BigInt(o.maxPriorityFeePerGas) : 1000000000n;
    const tx = { chainId: sess.profile.chainId, nonce, maxPriority, maxFee: o.maxFeePerGas ? BigInt(o.maxFeePerGas) : base * 2n + maxPriority, gas, to: o.to, value, data };
    const signed = signTx(key, tx);
    const ok = await ask({ type: 'confirmTx', site: sess.site, network: sess.profile.name, chainId: tx.chainId, from: address, txHash: signed.hash, raw: signed.raw, to: o.to, value: value.toString(), data, gas: gas.toString(), nonce: nonce.toString() });
    if (!ok) return E(4001, 'user rejected');
    return { result: await sess.rpc('eth_sendRawTransaction', [signed.raw]) };
  } catch (e) { return transportError(e); }
}

// ---------------- bridge port: one per viewer tab session ----------------
chrome.runtime.onConnect.addListener((port) => {
  if (!port.name.startsWith('bridge:')) return;
  const sid = port.name.slice(7); const sess = sessions.get(sid);
  if (!sess || !port.sender || !port.sender.tab || port.sender.tab.id !== sess.tabId) { port.disconnect(); return; }
  let asks = 0; const waiting = new Map(); let alive = true;
  const post = (m) => { if (alive) port.postMessage(m); };
  post({ hello: genId }); // D103 section 5: the viewer tears frames down if the worker generation changes
  const ask = (q) => new Promise((resolve) => { const id = ++asks; waiting.set(id, resolve); post({ ask: id, q }); });
  port.onMessage.addListener((msg) => {
    if (msg && msg.answer !== undefined) { const r = waiting.get(msg.answer); if (r) { waiting.delete(msg.answer); r(msg.ok === true); } return; }
    const arrivalMs = Math.floor(performance.now()); // stamped on receipt, before any check (D97)
    if (!msg || typeof msg !== 'object' || !Number.isInteger(msg.seq) || !Number.isInteger(msg.frame)) return;
    // Bpre-B3 run synchronously in arrival order; routing never blocks the next message.
    const c = bridge.check(sess.bucket, msg.text, arrivalMs);
    if (!c.ok) { post({ seq: msg.seq, frame: msg.frame, reply: c.reply }); return; }
    const ctl = { arrivalMs, ask, navigate: (to) => post({ navigate: to, frame: msg.frame }) };
    route(sess, c, ctl).then((r) => { if (!r.suppressed) post({ seq: msg.seq, frame: msg.frame, reply: { id: c.id, ...r } }); },
      () => post({ seq: msg.seq, frame: msg.frame, reply: { id: c.id, error: { code: -32603, message: 'internal' } } }));
  });
  port.onDisconnect.addListener(() => { alive = false; for (const r of waiting.values()) r(false); sessions.delete(sid); removeDnr(sess.tabId).catch(() => {}); });
});

// ---------------- messages from extension pages ----------------
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return false;
  (async () => {
    switch (msg.type) {
      case 'profiles.list': return { ok: true, profiles: await profiles() };
      case 'profiles.add': { const p = validateProfile(msg.profile); const list = (await profiles()).filter((x) => x.name !== p.name);
        if (list.some((x) => x.chainId === p.chainId && x.genesisHash !== p.genesisHash)) p.conflict = true;
        list.push(p); await store.set({ profiles: list }); return { ok: true, profile: p }; }
      case 'profiles.remove': await store.set({ profiles: (await profiles()).filter((x) => x.name !== msg.name) }); return { ok: true };
      case 'open': return await openSite({ ...msg, tabId: sender.tab ? sender.tab.id : undefined });
      case 'session.storage': { const s = sessions.get(msg.sessionId); if (!s || !sender.tab || sender.tab.id !== s.tabId) return { ok: false }; await booted; const snap = await records.load(s.netKey, s.site); return { ok: true, storage: snap.dict, storageError: snap.error || null }; }
      case 'wallet.create': { const seed = msg.seedHex ? fromHex(msg.seedHex) : crypto.getRandomValues(new Uint8Array(32)); if (seed.length !== 32) throw new Error('seed');
        await store.set({ wallet: await encryptSeed(seed, msg.password) }); unlocked = { seed, until: Date.now() + LOCK_MS }; return { ok: true }; }
      case 'wallet.unlock': { const w = (await store.get('wallet')).wallet; if (!w) return { ok: false, error: 'no wallet' }; unlocked = { seed: await decryptSeed(w, msg.password), until: Date.now() + LOCK_MS }; return { ok: true }; }
      case 'wallet.lock': unlocked = null; return { ok: true };
      case 'wallet.status': return { ok: true, exists: !!(await store.get('wallet')).wallet, unlocked: !!unlocked && Date.now() <= unlocked.until };
      case 'wallet.address': { const p = (await profiles()).find((x) => x.name === msg.name); if (!p || !unlocked) return { ok: false }; return { ok: true, address: addressOf(await networkKey(unlocked.seed, p.netKey)) }; }
      default: return { ok: false, error: 'unknown message' };
    }
  })().then(reply, (e) => reply({ ok: false, error: { code: e.code || -32603, message: String(e.message || e) } }));
  return true;
});

chrome.action.onClicked.addListener(() => chrome.runtime.openOptionsPage());

// omnibox: 'pocol <profile>/<0xaddr>[/path]'
chrome.omnibox.onInputEntered.addListener((text) => {
  chrome.tabs.update({ url: chrome.runtime.getURL('viewer.html') + '#' + encodeURI(text.trim()) });
});
