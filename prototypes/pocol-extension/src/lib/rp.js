// RP header window (browser.md D77, D80–D84): items 1, 1b, viewFuture, 2–9 and
// viewTargetCeil over n <= 13 headers. Items 10–17 are not evaluable by RP.
import * as rlp from './rlp.js';
import { keccak, sha256, recover } from './crypto.js';
import { concat, eq, be, toBig, fromHex, utf8 } from './hex.js';
export const VIEW_SLACK_S = 4n, PHI_VIEW = 10;
const MAX = (1n << 256n) - 1n;
export function decodeSpec(b) {
  const t = rlp.decode(b);
  if (!rlp.isList(t) || t.length !== 6) throw new Error('GenesisSpec shape');
  if (rlp.uint(t[0], 1) !== 1n) throw new Error('gsVersion');
  const cp = t[2].map((x) => rlp.uint(x, 32));
  if (cp.length !== 52) throw new Error('gsCount');
  return { chainId: rlp.uint(t[1], 8), cp, genesisHash: keccak(b) };
}
const CPI = { g_ts: 0, target_g: 1, T_blk: 2, tau: 3, nonceMode: 4, c: 5, D_att: 6, dFbWait: 7, m: 8, H_END: 45 };
export const cpv = (spec, k) => spec.cp[CPI[k]];
const floorDiv = (a, b) => { const q = a / b; return (a % b !== 0n && ((a < 0n) !== (b < 0n))) ? q - 1n : q; };
export function asert(targetG, gTs, tBlk, tau, pTs, pH) {
  const dt = (pTs - gTs) - tBlk * pH; const e = floorDiv(dt * 65536n, tau); const s = floorDiv(e, 65536n); const f = e - 65536n * s;
  if (s >= 256n) return MAX; if (s <= -257n) return 1n;
  const F = 65536n + floorDiv(195766423245049n * f + 971821376n * f * f + 5127n * f * f * f + (1n << 47n), 1n << 48n);
  const X = targetG * F; const k = s - 16n; const Y = k >= 0n ? X << k : X >> -k;
  return Y < 1n ? 1n : (Y > MAX ? MAX : Y);
}
export const work = (t) => (1n << 256n) / (t + 1n);
export function decodeHeader(b) {
  if (b.length > 3067) throw new Error('1 size');
  const top = rlp.decode(b);
  if (!rlp.isList(top) || top.length !== 4 || !rlp.isList(top[0]) || top[0].length !== 2) throw new Error('1 shape');
  const ut = top[0][0]; if (!rlp.isList(ut) || ut.length !== 18) throw new Error('1 UT');
  const tag = new TextDecoder().decode(rlp.bytes(ut[0])); if (tag !== 'PoCol-tpl-v1') throw new Error('1 tag');
  const f32 = (x) => { const v = rlp.bytes(x); if (v.length !== 32) throw new Error('1 hash'); return v; };
  const nonceB = rlp.bytes(top[1]); if (nonceB.length !== 8) throw new Error('1 nonce');
  const shares = top[2].map((s) => { const v = rlp.bytes(s); if (v.length !== 8) throw new Error('1 share'); return toBig(v); });
  if (shares.length > 256) throw new Error('1 shares');
  const wsig = rlp.bytes(top[3]); if (wsig.length !== 65) throw new Error('1 winnerSig');
  const sig = rlp.bytes(top[0][1]); const proposer = rlp.bytes(ut[17]);
  if (!(sig.length === 0 || sig.length === 65) || !(proposer.length === 0 || proposer.length === 20)) throw new Error('1 sig/proposer');
  const utRaw = rlp.encode(ut); const tid = sha256(utRaw); const shareRoot = keccak(rlp.encode(top[2]));
  return { chainId: rlp.uint(ut[1], 8), genesisHash: f32(ut[2]), parentHash: f32(ut[3]), h: rlp.uint(ut[4], 8), a: rlp.uint(ut[5], 4), version: rlp.uint(ut[6], 2), ts: rlp.uint(ut[7], 8),
    target: rlp.uint(ut[8], 32), proposer, sig, nonce: toBig(nonceB), nonceB, shares, winnerSig: wsig, tid, shareRoot, hash: keccak(concat(tid, nonceB, shareRoot)) };
}
const sigMsg = (tid) => keccak(concat(Uint8Array.of(0x19), utf8('PoCol template'), Uint8Array.of(0x0a), tid));
const winMsg = (x) => keccak(concat(Uint8Array.of(0x19), utf8('PoCol winner'), Uint8Array.of(0x0a), x.tid, x.nonceB, x.shareRoot));
/** Verifies the window; returns {ok, n, toGenesis, message} or throws {flag}. */
export async function verifyWindow(rpc, spec, clockS = Math.floor(Date.now() / 1000)) {
  const h = BigInt(await rpc('eth_blockNumber', []));
  if (h === 0n) return { ok: false, flag: 'viewNoBlocks', message: 'الشبكة لم تنتج الكتلة 1 بعد؛ لا رأس للتحقق في RP' };
  const b = h - 12n > 1n ? h - 12n : 1n; const from = b - 1n > 1n ? b - 1n : 1n; const count = h - from + 1n;
  const raw = await rpc('pocol_getHeaders', ['0x' + from.toString(16), '0x' + count.toString(16)]);
  if (!Array.isArray(raw) || BigInt(raw.length) !== count) throw Object.assign(new Error('viewIncomplete'), { flag: 'viewIncomplete' });
  const hs = raw.map((x) => decodeHeader(fromHex(x)));
  const tG = cpv(spec, 'target_g'), ceil = (tG << VIEW_SLACK_S) > MAX ? MAX : tG << VIEW_SLACK_S;
  const fail = (flag) => { throw Object.assign(new Error(flag), { flag }); };
  const netid = (x) => { if (x.chainId !== spec.chainId) fail('netChain'); if (!eq(x.genesisHash, spec.genesisHash)) fail('netGenesis'); if (x.version !== 1n) fail('netVersion'); if (x.ts > BigInt(clockS + PHI_VIEW)) fail('viewFuture'); };
  hs.forEach((x, i) => { if (x.h !== from + BigInt(i)) fail('viewIncomplete'); netid(x); });
  let parent = b > 1n ? hs[0] : { hash: spec.genesisHash, ts: cpv(spec, 'g_ts'), h: 0n };
  for (const x of hs.slice(b > 1n ? 1 : 0)) {
    if (!eq(x.parentHash, parent.hash) || x.h !== parent.h + 1n) fail(x.h === 1n ? 'viewGenesis' : '2');
    const signed = x.proposer.length > 0 || x.sig.length > 0;
    if (signed) { if (x.proposer.length !== 20 || x.sig.length !== 65 || x.a !== 0n) fail('3'); let r; try { r = recover(sigMsg(x.tid), x.sig); } catch { fail('3'); } if (!eq(r, x.proposer)) fail('3'); }
    const dAtt = cpv(spec, 'D_att'); const L = parent.ts + x.a * dAtt + 1n, U = parent.ts + (x.a + 1n) * dAtt;
    if (x.ts < L || x.ts > U) fail('4');
    if (!signed && x.ts !== (x.a === 0n ? L + cpv(spec, 'dFbWait') : L)) fail('4');
    const tgt = asert(tG, cpv(spec, 'g_ts'), cpv(spec, 'T_blk'), cpv(spec, 'tau'), parent.ts, parent.h);
    if (x.target !== tgt) fail('5');
    if (x.target > ceil) fail('viewTargetCeil');
    const cw = cpv(spec, 'c') * work(x.target); const nMax = cpv(spec, 'nonceMode') === 0n ? (cw < (1n << 64n) ? cw : 1n << 64n) : 1n << 64n;
    if (x.nonce >= nMax) fail('6');
    if (toBig(sha256(concat(x.tid, x.nonceB))) > x.target) fail('7');
    try { recover(winMsg(x), x.winnerSig); } catch { fail('8'); }
    const tShare = x.target * cpv(spec, 'm') > MAX ? MAX : x.target * cpv(spec, 'm');
    for (let i = 0; i < x.shares.length; i++) { const n = x.shares[i]; if ((i && n <= x.shares[i - 1]) || n === x.nonce || n >= nMax || toBig(sha256(concat(x.tid, be(n, 8)))) > tShare) fail('9'); }
    parent = x;
  }
  const n = h - b + 1n; const minWork = work(ceil);
  const message = `RP: مرتبط بالعمل والهوية لـ${n} رأسًا${b === 1n ? ' حتى genesis' : ''}، بعمل محتسب لا يقل عن ${minWork.toString(10)} لكل رأس (work(ceilTarget))، دون تحقق تنفيذ أو عضوية` + (minWork === 1n ? '. حد العمل غير فعال لهذه الشبكة' : '');
  return { ok: true, n: Number(n), toGenesis: b === 1n, minWork: minWork.toString(), head: Number(h), message };
}
