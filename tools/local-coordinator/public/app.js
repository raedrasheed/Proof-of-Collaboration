// Browser side. All rendering uses textContent / DOM nodes; no innerHTML, no Markdown rendering.
const $ = (id) => document.getElementById(id);
const token = location.hash.slice(1) || sessionStorage.getItem('pocol-coordinator-token') || '';
if (location.hash) { sessionStorage.setItem('pocol-coordinator-token', token); history.replaceState(null, '', '/'); }

// One idempotency key per pending action; reused until the server confirms, so a double
// click or a retry after a lost response cannot create a second request.
const pendingKeys = JSON.parse(sessionStorage.getItem('pocol-pending-keys') || '{}');
function keyFor(action) {
  if (!pendingKeys[action]) { pendingKeys[action] = crypto.randomUUID(); sessionStorage.setItem('pocol-pending-keys', JSON.stringify(pendingKeys)); }
  return pendingKeys[action];
}
function clearKey(action) { delete pendingKeys[action]; sessionStorage.setItem('pocol-pending-keys', JSON.stringify(pendingKeys)); }

async function api(url, data) {
  const res = await fetch(url, { method: data === undefined ? 'GET' : 'POST', headers: { 'X-PoCol-Control': token, 'Content-Type': 'application/json' }, body: data === undefined ? undefined : JSON.stringify(data) });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) { const e = new Error(body.error || `HTTP ${res.status}`); e.http = true; throw e; }
  return body;
}

function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined && text !== null) n.textContent = String(text); if (cls) n.className = cls; return n; }
function showError(t) { $('error').textContent = t || ''; $('error').hidden = !t; }
function setConnection(ok, text) { $('connection').textContent = text; $('connection').classList.toggle('lost', !ok); }
const na = (v) => (v === null || v === undefined || v === '' ? 'غير متاح' : String(v));

const STATE_AR = { queued: 'في الطابور', claimed: 'استلمه المنسق', acknowledged: 'أكد المنسق الاستلام', approved: 'وافق المنسق؛ ينتظر التشغيل', running: 'قيد التشغيل',
  completed: 'اكتمل؛ ينتظر مراجعة Codex', reviewed: 'رُوجع', failed: 'فشل', interrupted: 'انقطع', cancelled: 'أُلغي' };
const KIND_AR = { guidance: 'توجيه', ownerAnswer: 'إجابة سؤال مالك', authorJob: 'دورة مؤلف' };
const WAIT_AR = { idle: 'لا شيء معلق', workerRunning: 'مهمة المؤلف قيد التشغيل',
  workerFailed: 'آخر مهمة مؤلف فشلت أو انقطعت؛ بانتظار مراجعة Codex الفعلية لها، ثم إعادة صريحة إن طُلبت',
  waitingReview: 'بانتظار مراجعة Codex الفعلية؛ لن تبدأ دورة أخرى قبلها', waitingCoordinator: 'بانتظار المنسق ليستلم الطلبات',
  waitingReviewerAttach: 'المنسق المضيف غير متصل (دورة Codex الحالية غير نشطة)؛ الطلبات محفوظة وتنتظر اتصاله',
  dispatchBlocked: 'مهمة موافق عليها لكنها محجوبة؛ انظر السبب في الطابور', retryAvailable: 'رُوجعت المهمة الفاشلة؛ يمكن طلب إعادة صريحة' };
const PAUSE_AR = { active: 'يعمل', draining: 'إيقاف مطلوب؛ ينتظر انتهاء المهمة الجارية عند حد آمن', paused: 'متوقف مؤقتًا' };
const REVIEWER_AR = { attached: 'متصل', expired: 'انتهت مهلة الاتصال؛ لا مراجعة جارية الآن', disconnected: 'غير متصل' };

function renderStatus(v) {
  const s = v.status;
  $('phase').textContent = s.phaseAr;
  $('updatedAt').textContent = s.updatedAt;
  const c = s.latestCheck;
  $('latestCheck').textContent = c ? `المسودة ${c.revision}: ${c.summary.passed} ناجح، ${c.summary.recorded} مسجل، ${c.summary.failed} فاشل · ${na(c.executedAtUtc)} · ${c.source}` : 'غير متاح (لا يوجد ملف نتائج محفوظ)';
  const w = s.activeWorker;
  $('activeWorker').textContent = w ? `مهمة ${w.mode} · pid ${na(w.pid)} · بدأت ${na(w.startedAt)}` : `لا يوجد · سجل المنسق: ${s.ledgerActiveAuthor ? `${na(s.ledgerActiveAuthor.task)} (${na(s.ledgerActiveAuthor.state)})` : 'غير متاح'}`;
  $('reviewer').textContent = `${REVIEWER_AR[v.reviewer.status] || v.reviewer.status}${v.reviewer.heartbeatAt ? ' · آخر نبضة ' + v.reviewer.heartbeatAt : ''}`;
  $('pauseState').textContent = PAUSE_AR[v.pauseState] || v.pauseState;
  $('waiting').textContent = WAIT_AR[v.waiting] || v.waiting;
  $('findings').replaceChildren(...s.openFindings.map((f) => el('li', `${f.id} (${f.status}): ${f.decision || ''}`)));
  $('statusNote').textContent = s.noteAr;
  $('pause').disabled = v.pauseState !== 'active';
  $('resume').disabled = v.pauseState === 'active';
}

function renderQueue(v) {
  const box = $('queue');
  if (!v.items.length) { box.replaceChildren(el('p', 'لا توجد طلبات بعد.', 'empty')); return; }
  box.replaceChildren(...v.items.slice().reverse().map((i) => {
    const d = el('div', null, 'item');
    const head = el('div', KIND_AR[i.kind] || i.kind);
    head.append(el('span', STATE_AR[i.status] || i.status, `state ${i.status}`));
    d.append(head);
    if (i.payload?.text) d.append(el('p', i.payload.text));
    if (i.kind === 'ownerAnswer') d.append(el('p', `${i.payload.questionId}: ${i.payload.choice}${i.payload.testOnly ? ' (اختبار فقط)' : ''}${i.payload.note ? ' · ' + i.payload.note : ''}`));
    if (i.kind === 'authorJob') d.append(el('p', `النوع: ${i.payload.mode}${i.dispatch?.plannedDir ? ' · المجلد ' + i.dispatch.plannedDir : ''}${i.blockedReason ? ' · محجوب: ' + i.blockedReason : ''}${i.error ? ' · خطأ: ' + i.error : ''}`));
    if (i.receipt?.result) d.append(el('pre', i.receipt.result.text || '(لا يوجد نص نتيجة)', 'tech'));
    if (i.kind === 'authorJob' && ['completed', 'failed', 'interrupted'].includes(i.status)) {
      const rv = i.reviewId ? v.reviews.find((r) => r.id === i.reviewId) : null;
      d.append(el('p', i.reviewId ? `رُوجعت فعليًا: ${rv ? rv.verdict + ' · ' + rv.reviewerId + ' · ' + rv.at : i.reviewId}` : 'لم تُراجع بعد؛ لن تبدأ أي مهمة أخرى قبل مراجعة Codex الفعلية.', 'muted'));
    }
    // A failed or interrupted job keeps its retry button after its review; the retry still
    // needs the coordinator's approval and only starts once the failure has been reviewed.
    if (i.kind === 'authorJob' && ['failed', 'interrupted'].includes(i.status)) {
      const b = el('button', i.reviewId ? 'طلب إعادة صريحة من نقطة التثبيت' : 'طلب إعادة صريحة (تبدأ بعد مراجعة الفشل)', 'secondary');
      b.addEventListener('click', () => act(`retry-${i.id}`, '/api/retry', { mode: i.payload.mode, retryOf: i.id, note: 'إعادة صريحة لمهمة فاشلة' }));
      d.append(b);
    }
    d.append(el('div', `${i.id} · ${i.createdAt}`, 'meta'));
    return d;
  }));
}

let ownerSig = null;
function renderOwner(v) {
  // Re-render only when stored answers change, so an answer being typed is not wiped by polling.
  const sig = JSON.stringify(v.owner.map((q) => q.answer));
  if (sig === ownerSig) return;
  ownerSig = sig;
  $('owner').replaceChildren(...v.owner.map((q) => {
    const card = el('div', null, `owner-card${q.testOnly ? ' test' : ''}`);
    card.append(el('h3', `${q.id} · ${q.titleAr}${q.testOnly ? ' — اختبار فقط، لا يعتمد سياسة' : ''}`), el('p', q.questionAr), el('p', 'لماذا: ' + q.whyAr, 'muted'), el('p', 'التوصية: ' + q.recommendationAr));
    const opts = el('div', null, 'options');
    for (const o of q.options) {
      const label = el('label');
      const r = document.createElement('input'); r.type = 'radio'; r.name = `q-${q.id}`; r.value = o.id;
      label.append(r, el('span', `${o.labelAr} — النتيجة: ${o.consequenceAr}`));
      opts.append(label);
    }
    const note = document.createElement('textarea'); note.rows = 2; note.maxLength = 2000; note.placeholder = 'ملاحظة اختيارية'; note.setAttribute('aria-label', `ملاحظة ${q.id}`);
    const send = el('button', 'حفظ الإجابة وتسليمها للمنسق', 'secondary');
    send.addEventListener('click', () => {
      const chosen = opts.querySelector('input:checked');
      if (!chosen) return showError('اختر خيارًا أولًا.');
      act(`owner-${q.id}`, '/api/owner-answer', { questionId: q.id, choice: chosen.value, note: note.value });
    });
    card.append(opts, note, send);
    if (q.answer) card.append(el('p', `آخر إجابة محفوظة: ${q.answer.choice} · ${STATE_AR[q.answer.status] || q.answer.status} · ${q.answer.at}`, 'answer'));
    return card;
  }));
}

const ROLE = { author: ['CLAUDE · المؤلف', 'author'], reviewer: ['CODEX · المراجع', 'reviewer'], coordinator: ['المنسق · مهمة', 'coordinator'] };
function renderHistory(cards) {
  const current = cards.filter((c) => c.current).length;
  $('historyCount').textContent = `${cards.length} بطاقة (${current} حالية)`;
  $('history').replaceChildren(...cards.map((c) => {
    const a = el('article', null, `message ${c.role === 'reviewer' ? 'codex' : ''}`);
    const h = el('h3');
    const [label, cls] = ROLE[c.role] || [c.role, ''];
    h.append(el('span', label, `badge ${cls}`), el('span', c.current ? 'حالية' : 'تاريخية', 'badge'), el('span', c.summaryAr));
    a.append(h);
    a.append(el('p', [`time: ${c.time ?? 'unavailable'}${c.timeNote ? ' (' + c.timeNote + ')' : ''}`, c.jobId ? `job: ${c.jobId}` : null,
      c.verdict ? `verdict: ${c.verdict}` : null, c.reviewerId ? `reviewer: ${c.reviewerId}` : null,
      c.task ? `task: ${c.task}` : null, c.revision ? `revision: ${c.revision}` : null,
      c.sha256 ? `sha256: ${c.sha256.slice(0, 16)}…` : null, c.commit ? `commit: ${String(c.commit).slice(0, 12)}` : null, `source: ${c.source}`].filter(Boolean).join(' · '), 'meta'));
    const det = el('details'); det.append(el('summary', 'النص التقني (بالإنجليزية)'));
    if (c.result) { det.append(el('div', `result · error=${c.result.isError} · turns=${na(c.result.numTurns)} · permission denials=${c.result.permissionDenials.length}`, 'entry-kind'), el('pre', c.result.text || '(empty)', 'tech')); }
    for (const e of c.technical || []) {
      if (e.kind === 'tool_use') det.append(el('div', `tool call: ${e.name} ${e.at ? '· ' + e.at : ''}`, 'entry-kind'), el('pre', JSON.stringify(e.input, null, 1), 'tech'));
      else det.append(el('div', `${e.kind}${e.isError ? ' (error)' : ''} ${e.at ? '· ' + e.at : ''}`, 'entry-kind'), el('pre', e.text, 'tech'));
    }
    if (c.truncatedEntries) det.append(el('p', `حُذف ${c.truncatedEntries} إدخالًا أقدم من العرض.`, 'muted'));
    a.append(det);
    return a;
  }));
}

async function act(action, url, data) {
  showError('');
  try {
    await api(url, { ...data, idempotencyKey: keyFor(action) });
    clearKey(action);
    if (action === 'guidance') $('guidance').value = '';
    await refresh();
  } catch (e) {
    showError(e.http ? e.message : 'انقطع الاتصال بالخادم المحلي. الطلب محفوظ بمفتاحه؛ أعد الإرسال بعد عودة الاتصال ولن يتكرر.');
  }
}

$('sendGuidance').addEventListener('click', () => act('guidance', '/api/guidance', { text: $('guidance').value }));
$('requestJob').addEventListener('click', () => act(`job-${$('jobMode').value}`, '/api/author-job', { mode: $('jobMode').value, note: $('guidance').value.trim() ? $('guidance').value : '' }));
$('pause').addEventListener('click', () => act('pause', '/api/pause', {}));
$('resume').addEventListener('click', () => act('resume', '/api/resume', { reason: 'استئناف من الواجهة' }));

async function refresh() {
  try {
    const v = await api('/api/state');
    setConnection(true, `متصل بالخادم المحلي · ${new Date().toLocaleTimeString('ar')}`);
    renderStatus(v); renderQueue(v); renderOwner(v);
    // Current Claude receipts and Codex reviews join the timeline on the ordinary poll:
    // the timeline is refetched whenever the server's signature of current cards changes.
    if (v.timelineSig !== timelineSig) { timelineSig = v.timelineSig; await loadHistory(); }
  } catch (e) {
    setConnection(false, e.http ? `رفض الخادم الطلب: ${e.message}` : 'انقطع الاتصال بالخادم المحلي (الخادم متوقف أو الشبكة المحلية غير متاحة). لم يُفقد أي طلب محفوظ.');
  }
}
let timelineSig = null;
async function loadHistory() {
  try { renderHistory((await api('/api/history')).cards); }
  catch (e) { timelineSig = null; $('history').replaceChildren(el('p', 'تعذر تحميل السجل: ' + e.message, 'empty')); }
}
async function poll() { await refresh(); setTimeout(poll, 2500); }
poll(); setInterval(loadHistory, 60_000);
