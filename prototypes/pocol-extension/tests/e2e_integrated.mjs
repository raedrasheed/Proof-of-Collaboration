// LP10 integrated devnet suite: fresh directory, 3 Rust nodes, >= 100 live blocks,
// website publish/update/read across all nodes and real Chrome, partition with a
// site update on the minority branch, heal/reorg, SIGKILL + full restart, replay,
// identical canonical roots/receipts/content, resource measurements.
import { spawn, spawnSync } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { mkdtempSync, readFileSync, writeFileSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { build } from '../build.mjs';
import { EXT, BIN, sleep, wait, checker, devnet, rpc, portFree, png2x2, writeSite, publish, openBrowser, siteFrame, openSite } from './harness.mjs';

const { ok, results, failed } = checker();
const work = mkdtempSync(join(tmpdir(), 'pocol-lp10-'));
const H = (n) => Number(n);
const height = async (i) => H(await rpc(8540 + i, 'eth_blockNumber'));
const heights = () => Promise.all([0, 1, 2].map(height));
const CURRENT = '0x9fa6a6e3';
const currentVersion = async (i, site) => Number(BigInt('0x' + (await rpc(8540 + i, 'eth_call', [{ to: site, data: CURRENT }, 'latest'])).slice(2, 66)));
const post = (port, body, origin) => new Promise((res, rej) => {
  const h = { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }; if (origin) h.origin = origin;
  const r = httpRequest({ host: '127.0.0.1', port, method: 'POST', path: '/', headers: h }, (x) => { let d = ''; x.on('data', (c) => { d += c; }); x.on('end', () => res(JSON.parse(d))); });
  r.on('error', rej); r.end(body);
});
const site = (v) => ({
  'index.html': `<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="s.css"><title>LP10 v${v}</title></head><body><h1 id="t">LP10 site v${v}</h1><img id="i" src="i.png"><script src="a.js"></script></body></html>`,
  's.css': 'h1{color:#1a5}', 'a.js': `document.getElementById('t').dataset.v='${v}';`, 'i.png': png2x2(),
  'big.txt': `v${v} ` + 'lp10 '.repeat(9000),
});
const sha = (b) => createHash('sha256').update(b).digest('hex').slice(0, 16);
function fetchCli(i, s) {
  const out = mkdtempSync(join(tmpdir(), 'pocol-fetch-'));
  const r = spawnSync(BIN('pocol-site'), ['fetch', '--rpc', `127.0.0.1:${8540 + i}`, '--site', s, '--out', out], { encoding: 'utf8' });
  if (r.status) throw new Error(r.stderr); const m = JSON.parse(r.stdout);
  return { version: m.version, digest: sha(Buffer.concat(m.files.map((f) => Buffer.concat([Buffer.from(f.path), readFileSync(join(out, f.path.slice(1)))])))) };
}
let isolated = null;
const startIsolatedC = () => { isolated = spawn(BIN('pocold'), ['run', '--network', join(work, 'net'), '--data', join(work, 'data', 'c'), '--name', 'c', '--miner', 'c', '--rpc', '127.0.0.1:8542', '--log'], { stdio: 'ignore', detached: true }); };
const stopIsolatedC = async () => { if (isolated) { process.kill(-isolated.pid, 'SIGTERM'); await new Promise((r) => isolated.once('exit', r)); isolated = null; } };
const pids = () => JSON.parse(readFileSync(join(work, 'pids.json'), 'utf8'));
const rssKiB = (pid) => { try { return Number(/VmRSS:\s+(\d+)/.exec(readFileSync(`/proc/${pid}/status`, 'utf8'))[1]); } catch { return null; } };

async function chromeView(b, profile, s) {
  const { page, errors } = await openSite(b, profile, s); const { fr } = await siteFrame(page);
  const v = await fr.evaluate(() => ({ h1: document.getElementById('t').textContent, v: document.getElementById('t').dataset.v, color: getComputedStyle(document.getElementById('t')).color, img: document.getElementById('i').naturalWidth }));
  const ver = await page.textContent('#ver'); const trust = await page.getAttribute('#trust', 'data-level'); await page.close();
  return { ...v, ver, trust, errors: errors.length };
}

async function main() {
  for (const p of [30300, 30301, 30302, 8540, 8541, 8542]) if (!(await portFree(p))) throw new Error('port busy ' + p);
  const t0 = Date.now();
  devnet(['init', work, '--miners', 'a,b,c', '--t-blk', '2', '--tau', '20', '--d-att', '4', '--fb-wait', '1', '--work-bits', '15']);
  const info = JSON.parse(readFileSync(join(work, 'net', 'devnet.json'), 'utf8')); const cid = String(info.chainId);
  const profile = JSON.parse(readFileSync(join(work, 'net', 'profile.json'), 'utf8'));
  devnet(['start', work, '--log']);
  try {
    await wait(async () => Math.min(...await heights()) >= 16, 240000, 'height 16');
    ok('fresh-directory launch: 3 pocold processes produce and agree', (await Promise.all([0, 1, 2].map((i) => rpc(8540 + i, 'eth_getBlockByNumber', ['0x8', false])))).every((x, _, a) => x.hash === a[0].hash), `t=${((Date.now() - t0) / 1000).toFixed(0)}s`);
    // BR15 (governance ORIGIN_DENY): mining interfaces refuse any request carrying an Origin; without Origin they are served.
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'pocol_getTemplate', params: [] });
    const withO = await post(8540, body, 'chrome-extension://abcdefghijklmnop'), noO = await post(8540, body, null);
    ok('BR15 pocol_getTemplate with Origin -> -32601; without Origin -> served', withO.error && withO.error.code === -32601 && noO.result !== undefined, JSON.stringify(withO.error));
    const d1 = join(work, 's1'); writeSite(d1, site(1)); const S = publish(d1, 8540, cid).site;
    await wait(async () => (await Promise.all([0, 1, 2].map((i) => currentVersion(i, S).catch(() => -1)))).every((v) => v === 0), 180000, 'v1 everywhere');
    const cli1 = [0, 1, 2].map((i) => fetchCli(i, S));
    ok('v1 published through node a; pocol-site fetch from every node gives identical verified bytes', cli1.every((x) => x.version === 0 && x.digest === cli1[0].digest), cli1.map((x) => x.digest).join(','));

    const dist = build().dist; const b = await openBrowser(dist, 'lp10');
    for (const [i, l] of ['a', 'b', 'c'].entries()) await b.send({ type: 'profiles.add', profile: { ...profile, name: 'node-' + l, endpoint: `http://127.0.0.1:${8540 + i}`, trustLevel: 'LN' } });
    await b.send({ type: 'profiles.add', profile: { ...profile, name: 'rp-a', endpoint: 'http://127.0.0.1:8540', trustLevel: 'RP' } });
    const v1 = await Promise.all(['a', 'b', 'c'].map((l) => chromeView(b, 'node-' + l, S)));
    ok('Chrome renders v1 identically through each node (HTML/CSS/JS/PNG from verified chunks)', v1.every((x) => x.h1 === 'LP10 site v1' && x.v === '1' && x.color === 'rgb(17, 170, 85)' && x.img === 2 && x.errors === 0), JSON.stringify(v1[0]));
    const rp = await chromeView(b, 'rp-a', S); ok('Chrome RP profile accepts the live window and renders v1', rp.trust === 'RP' && rp.h1 === 'LP10 site v1', rp.trust);

    // ---- partition: c isolated, v2 published on the minority branch through c ----
    devnet(['stop', work]); await sleep(1500); // stop all, then restart a+b meshed and c alone
    const ab = (l, i) => spawn(BIN('pocold'), ['run', '--network', join(work, 'net'), '--data', join(work, 'data', l), '--name', l, '--miner', l, '--listen', `127.0.0.1:${30300 + i}`, '--rpc', `127.0.0.1:${8540 + i}`, '--peer', `127.0.0.1:${30300 + (1 - i)}`, '--log'], { stdio: 'ignore', detached: true });
    const pa = ab('a', 0), pb = ab('b', 1); startIsolatedC();
    const base = Math.min(...await wait(async () => { try { return await heights(); } catch { return null; } }, 60000, 'partitioned nodes up'));
    const d2 = join(work, 's2'); writeSite(d2, site(2)); publish(d2, 8542, cid, S);
    await wait(async () => (await currentVersion(2, S)) === 1, 240000, 'v2 on isolated c');
    const vC = await chromeView(b, 'node-c', S), vA = await chromeView(b, 'node-a', S);
    ok('partition: Chrome via isolated c shows v2 (minority branch) while a shows v1', vC.h1 === 'LP10 site v2' && vA.h1 === 'LP10 site v1', `${vC.h1} / ${vA.h1}`);
    await wait(async () => { const [ha, , hc] = await heights(); return ha > hc + 4; }, 240000, 'majority branch heavier');
    const cTip = (await rpc(8542, 'pocol_status')).head, aTip = (await rpc(8540, 'pocol_status')).head;
    ok('partition: branches diverged', cTip.hash !== aTip.hash, `c=${cTip.height} ab=${aTip.height} base=${base}`);
    // ---- heal ----
    await stopIsolatedC(); for (const p of [pa, pb]) process.kill(-p.pid, 'SIGTERM'); await sleep(1500);
    devnet(['start', work, '--log']);
    await wait(async () => { const s = await Promise.all([0, 1, 2].map((i) => rpc(8540 + i, 'pocol_status'))); return s[2].head.height >= s[0].head.height - 1 && s[2].stats.reorgs >= 1; }, 240000, 'c reorganized');
    const stC = await rpc(8542, 'pocol_status');
    ok('heal: c reorganized onto the heavier branch (D133)', stC.stats.reorgs >= 1, JSON.stringify(stC.stats));
    await wait(async () => { const v = await Promise.all([0, 1, 2].map((i) => currentVersion(i, S))); return v.every((x) => x === v[0]) && v; }, 120000, 'site state agrees');
    const afterHeal = await Promise.all(['a', 'b', 'c'].map((l) => chromeView(b, 'node-' + l, S)));
    const canon = await currentVersion(0, S);
    ok('reorg recovery: Chrome via c now shows the canonical version, identical on all nodes', afterHeal.every((x) => x.h1 === afterHeal[0].h1 && x.ver === afterHeal[0].ver) && afterHeal[0].h1 === `LP10 site v${canon + 1}`, `${afterHeal.map((x) => x.h1).join(' | ')} (canonical index ${canon})`);
    // ---- v3 through b on the healed network ----
    const d3 = join(work, 's3'); writeSite(d3, site(3)); publish(d3, 8541, cid, S);
    await wait(async () => (await Promise.all([0, 1, 2].map((i) => fetchCli(i, S)))).every((x, _, a) => x.digest === a[0].digest && x.digest !== cli1[0].digest && x.version === a[0].version) , 240000, 'v3 everywhere');
    const v3 = await Promise.all(['a', 'b', 'c'].map((l) => chromeView(b, 'node-' + l, S)));
    ok('update: v3 published through b is read identically through every node in Chrome', v3.every((x) => x.h1 === 'LP10 site v3' && x.v === '3'), v3.map((x) => x.ver).join(' | '));
    // ---- crash + full restart ----
    process.kill(pids().b, 'SIGKILL'); await sleep(1500); devnet(['stop', work, '--only', 'b']);
    devnet(['start', work, '--log', '--only', 'b']);
    await wait(async () => { const h = await heights(); return Math.abs(h[1] - h[0]) <= 1; }, 120000, 'b recovered');
    ok('SIGKILL: b restarts from its journal and rejoins', true, (await heights()).join(','));
    await wait(async () => Math.min(...await heights()) >= 106, 900000, '>= 106 blocks');
    devnet(['stop', work]); await sleep(1500); devnet(['start', work, '--log']);
    await wait(async () => { try { await heights(); return true; } catch { return false; } }, 60000, 'restart');
    const afterRestart = await Promise.all(['a', 'b', 'c'].map((l) => chromeView(b, 'node-' + l, S)));
    ok('full restart: site served unchanged through every node in Chrome (journal replay)', afterRestart.every((x) => x.h1 === 'LP10 site v3'), afterRestart.map((x) => x.h1).join(' | '));
    // ---- convergence over the confirmed common prefix ----
    const CONFIRM = 6; let top = 0;
    await wait(async () => { const t = Math.min(...await heights()) - CONFIRM; if (t < 100) return false; const hs = await Promise.all([0, 1, 2].map((i) => rpc(8540 + i, 'eth_getBlockByNumber', ['0x' + t.toString(16), false]))); if (hs.every((x) => x.hash === hs[0].hash)) { top = t; return true; } return false; }, 300000, 'confirmed prefix >= 100');
    const mism = []; const live = [];
    for (let n = 1; n <= top; n++) { const bs = await Promise.all([0, 1, 2].map((i) => rpc(8540 + i, 'eth_getBlockByNumber', ['0x' + n.toString(16), false]))); live.push(bs[0]); if (!bs.every((x) => x.hash === bs[0].hash && x.stateRoot === bs[0].stateRoot && x.receiptsRoot === bs[0].receiptsRoot)) mism.push(n); }
    ok(`identical canonical hash/stateRoot/receiptsRoot at heights 1..${top} on 3 nodes`, mism.length === 0 && top >= 100, mism.slice(0, 5).join(','));
    // ---- resources ----
    const res = {}; for (const [l, pid] of Object.entries(pids())) res[l] = { rssMiB: +(rssKiB(pid) / 1024).toFixed(1), journalMiB: +(statSync(join(work, 'data', l, 'blocks.journal')).size / 1048576).toFixed(2) };
    ok('resources: node RSS < 512 MiB and journal < 64 MiB after >= 100 blocks', Object.values(res).every((r) => r.rssMiB > 0 && r.rssMiB < 512 && r.journalMiB < 64), JSON.stringify(res));
    const cdp = await b.ctx.newCDPSession(b.opt); await cdp.send('Performance.enable'); const pm = Object.fromEntries((await cdp.send('Performance.getMetrics')).metrics.map((m) => [m.name, m.value]));
    ok('resources: extension page JS heap measured', pm.JSHeapUsedSize > 0, `${(pm.JSHeapUsedSize / 1048576).toFixed(1)} MiB`);
    await b.close();
    // ---- replay: stop, reopen each journal peerless, compare roots and content ----
    devnet(['stop', work]); await sleep(1500);
    let refDigest = null; // content digest from the first replayed node (only one replay process runs at a time)
    for (const [i, l] of ['a', 'b', 'c'].entries()) {
      const p = spawn(BIN('pocold'), ['run', '--network', join(work, 'net'), '--data', join(work, 'data', l), '--name', l + '-replay', '--rpc', `127.0.0.1:${8540 + i}`], { stdio: 'ignore', detached: true });
      try {
        await wait(async () => { try { return await rpc(8540 + i, 'pocol_status'); } catch { return null; } }, 60000, 'replay ' + l);
        let bad = 0; for (const x of live) { const y = await rpc(8540 + i, 'eth_getBlockByNumber', [x.number, false]); if (y.hash !== x.hash || y.stateRoot !== x.stateRoot || y.receiptsRoot !== x.receiptsRoot) bad++; }
        const f = fetchCli(i, S); if (refDigest === null) refDigest = f.digest;
        ok(`replay of ${l}: re-executed canonical roots 1..${top} identical, site bytes identical`, bad === 0 && f.digest === refDigest, `${f.digest}`);
      } finally { process.kill(-p.pid, 'SIGTERM'); await sleep(500); }
    }
    writeFileSync(join(work, 'resources.json'), JSON.stringify(res, null, 1));
  } finally {
    await stopIsolatedC().catch(() => {}); try { devnet(['stop', work]); } catch {}
  }
}

try { await main(); } catch (e) { ok('LP10 driver completed', false, e.stack || e.message); }
const summary = { result: failed() ? 'FAIL' : 'PASS', checks: results.length, failed: failed(), work };
writeFileSync(join(EXT, 'tests', 'e2e_integrated.last.json'), JSON.stringify({ ...summary, results }, null, 1) + '\n');
console.log(JSON.stringify(summary));
process.exit(failed() ? 1 : 0);
