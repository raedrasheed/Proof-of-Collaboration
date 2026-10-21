// Viewer (browser.md D26): fixes the context, asks the worker to fetch and verify,
// hosts the site in a sandboxed frame, relays bridge text to the worker unparsed,
// shows confirmations outside the frame, tears the frame down on a second load.
const $ = (id) => document.getElementById(id);
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const TARGET = /^([A-Za-z0-9_-]{1,32})\/(0x[0-9a-fA-F]{40})(\/[\x21-\x7e]*)?$/;

let ctx = null; // {name, site, sessionId, port, files, frame, current}
const status = (t) => { $('status').textContent = t; };
const fail = (t) => { $('stage').replaceChildren(Object.assign(document.createElement('p'), { className: 'err', textContent: t })); status(''); };

// Confirmations are serialized; each resolves true only by an explicit click on "approve".
const confirms = []; let showing = false;
function confirmUI(q) {
  return new Promise((resolve) => { confirms.push({ q, resolve }); pump(); });
}
function pump() {
  if (showing || !confirms.length) return;
  showing = true; const { q, resolve } = confirms.shift();
  const titles = { confirmExternal: 'فتح رابط خارجي في تبويب جديد', confirmAccounts: 'منح الموقع حسابك على هذه الشبكة', confirmTx: 'توقيع معاملة وإرسالها' };
  $('mtitle').textContent = titles[q.type] || q.type;
  $('mtext').textContent = q.type === 'confirmExternal' ? q.url
    : q.type === 'confirmAccounts' ? `site: ${q.site}\nnetwork: ${q.network}\naccount: ${q.address}`
    : `network: ${q.network} (chainId ${q.chainId})\nsite: ${q.site}\nfrom: ${q.from}\nto: ${q.to}\nvalue (wei): ${q.value}\ngas: ${q.gas}\nnonce: ${q.nonce}\ndata: ${q.data}\ntxHash: ${q.txHash}\nraw: ${q.raw}`;
  $('modal').hidden = false; $('modal').dataset.kind = q.type;
  const done = (ok) => { $('approve').onclick = $('reject').onclick = null; $('modal').hidden = true; showing = false; resolve(ok); pump(); };
  $('approve').onclick = () => done(true); $('reject').onclick = () => done(false);
}

function teardown(reason) {
  const c = ctx.current; if (!c) return;
  ctx.current = null; try { c.channel.port1.close(); } catch {}
  c.iframe.remove(); if (reason) status(reason);
}
async function mount(path, opts = {}) {
  teardown();
  const frame = ++ctx.frame;
  const storage = opts.storage || (await chrome.runtime.sendMessage({ type: 'session.storage', sessionId: ctx.sessionId })).storage || {};
  if (frame !== ctx.frame) return;
  const iframe = document.createElement('iframe');
  iframe.setAttribute('sandbox', 'allow-scripts allow-forms');
  iframe.setAttribute('referrerpolicy', 'no-referrer');
  iframe.id = 'site'; iframe.dataset.frame = String(frame); iframe.src = 'sandbox.html';
  const channel = new MessageChannel(); const cur = { iframe, channel, frame };
  let loads = 0;
  iframe.addEventListener('load', () => {
    loads++;
    if (loads > 1) { teardown('أُزيل الإطار: حاول الموقع الانتقال بنفسه (D26)'); return; }
    // Bridge text is forwarded as-is; only the envelope {seq, text} shape is checked here.
    channel.port1.onmessage = (e) => {
      const m = e.data; if (!ctx.current || ctx.current.frame !== frame) return;
      if (!m || typeof m !== 'object' || !Number.isInteger(m.seq) || typeof m.text !== 'string') return;
      ctx.port.postMessage({ seq: m.seq, frame, text: m.text });
    };
    const files = {}; for (const [p, f] of ctx.files) files[p] = { mime: f.mime, data: f.data };
    iframe.contentWindow.postMessage({ type: 'pocol-init', files, path, entry: ctx.entry, storage, notFound: !!opts.notFound, requested: opts.requested, version: ctx.version }, '*', [channel.port2]);
  });
  ctx.current = cur; $('stage').replaceChildren(iframe);
  history.replaceState(null, '', '#' + ctx.name + '/' + ctx.site + (opts.requested || path));
  status(opts.notFound ? '404' : path);
}

// D103 section 5: worker gone or replaced -> tear frames down, announce possible loss, reload only by the user.
function workerLost() {
  if (!ctx) return; teardown(); ctx.current = null; ctx.frame = Number.MAX_SAFE_INTEGER;
  const p = Object.assign(document.createElement('p'), { className: 'err', textContent: 'انقطع عامل الإضافة؛ قد تكون آخر الكتابات غير محفوظة ' });
  const b = Object.assign(document.createElement('button'), { type: 'button', id: 'reload', textContent: 'إعادة التحميل' }); b.onclick = () => location.reload();
  p.append(b); $('stage').replaceChildren(p); status('');
}
async function start() {
  const t = TARGET.exec(decodeURI(location.hash.slice(1)));
  if (!t) { fail('العنوان: #<profile>/<0x…address>[/path]'); return; }
  const [, name, site, path = '/'] = t;
  $('where').textContent = `${name}/${site}`; status('جارٍ الجلب والتحقق…');
  const r = await chrome.runtime.sendMessage({ type: 'open', name, site, path });
  if (!r || !r.ok) { fail('تعذر فتح الموقع: ' + (r && r.error ? (r.error.message || r.error) : 'unknown')); $('trust').textContent = 'رُفض'; return; }
  $('trust').textContent = r.trust.message; $('trust').className = 'badge ' + r.trust.level; $('trust').dataset.level = r.trust.level;
  $('ver').textContent = `version ${r.version} · block ${r.publishedBlock}`;
  const files = new Map(); for (const p of Object.keys(r.files)) files.set(p, { mime: r.files[p].mime, data: unb64(r.files[p].b64) });
  const port = chrome.runtime.connect({ name: 'bridge:' + r.sessionId });
  ctx = { name, site, sessionId: r.sessionId, port, files, frame: 0, current: null, entry: r.entry, version: r.version };
  port.onMessage.addListener(async (m) => {
    if (m.hello !== undefined) { if (ctx.genId && ctx.genId !== m.hello) workerLost(); ctx.genId = m.hello; return; }
    if (m.ask !== undefined) { const ok = await confirmUI(m.q); port.postMessage({ answer: m.ask, ok }); return; }
    if (!ctx.current || m.frame !== ctx.current.frame) return; // replies to a torn-down frame are dropped (D99)
    if (m.navigate) {
      const to = m.navigate;
      if (to.notFound || !ctx.files.has(to.path === '' ? ctx.entry : to.path)) await mount(ctx.entry, { notFound: true, requested: to.path });
      else await mount(to.path === '' ? ctx.entry : to.path);
      return;
    }
    ctx.current.channel.port1.postMessage({ seq: m.seq, reply: m.reply });
  });
  port.onDisconnect.addListener(workerLost);
  await mount(r.path, { storage: r.storage, notFound: r.notFound, requested: r.notFound ? path : undefined });
}
start().catch((e) => fail(String(e && e.message ? e.message : e)));
