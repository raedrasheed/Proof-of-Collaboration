"""TRACK journal r3: derived figures for JOURNAL-GROWTH-AND-REPLAY.md from the committed measurement logs.

Stdlib only; run as `python3 -I tools/journal_projections.py <evidence dir>` from
development/audit-2026-10-22. Reads the JM-* JSON lines of evidence/journal-r3/*.log (and the stage-A
JM-REPLAY points of evidence/journal-measure.log, the r2 JM-KIND of evidence/journal-measure-r2.log) and
prints every number the report derives from them. Projections are arithmetic on measured per-block
costs; they are not measurements of a chain of that height or of the network profile, which pocold
refuses to boot.
"""
import json
import os
import re
import sys

PAT = re.compile(r'(JM-[A-Z0-9-]+) (\{.*\})\s*$')
GIB = 1 << 30
DEV = dict(H_END=20_000, TX_CAP=20_000, TXBYTES_CAP=1 << 24, SLOT_CAP=50_000, ACCT_CAP=20_000, T_blk=4, D_att=25)
NET = dict(H_END=129_600, TX_CAP=10_000_000, TXBYTES_CAP=1 << 33, SLOT_CAP=4_000_000, ACCT_CAP=1_000_000, T_blk=60, D_att=300)


def lines(path, tag):
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path):
        m = PAT.search(line)
        if m and m.group(1) == tag:
            out.append(json.loads(m.group(2)))
    return out


def fit(points):
    """Least squares of t = a*H + c*H^2 (c = b/2), no intercept."""
    s11 = sum(h * h for h, _ in points); s12 = sum(h ** 3 for h, _ in points); s22 = sum(h ** 4 for h, _ in points)
    r1 = sum(h * t for h, t in points); r2 = sum(h * h * t for h, t in points)
    det = s11 * s22 - s12 * s12
    a = (r1 * s22 - r2 * s12) / det; c = (s11 * r2 - s12 * r1) / det
    return a, c


def two_point(p, q):
    (h1, t1), (h2, t2) = p, q
    c = (t2 / h2 - t1 / h1) / (h2 - h1); a = t1 / h1 - c * h1
    return a, c


def hms(s):
    return '%.0f s = %.1f min = %.2f h' % (s, s / 60, s / 3600)


def main(ev):
    r3 = os.path.join(ev, 'journal-r3')
    P = lambda n: os.path.join(r3, n)
    print('== journal r3 derived figures: python3 -I tools/journal_projections.py %s (from development/audit-2026-10-22) ==' % ev)
    print('Inputs: journal-r3/*.log (code 7f587bb), journal-measure.log (stage-A JM-REPLAY), journal-measure-r2.log (round 2).')
    print('Projections are arithmetic on measured per-block costs, not measurements of a chain of that height.')

    # ---- 1. open replay fit (empty blocks) ----
    sa = [(d['height'], d['openSeconds']) for d in lines(os.path.join(ev, 'journal-measure.log'), 'JM-REPLAY')]
    rr = [(d['height'], d['openSeconds']) for d in lines(P('replay-empty.log'), 'JM-REPLAY')]
    o0 = lines(P('replay-kind.log'), 'JM-OPEN0'); o0 = o0[0]['openSecondsMedian'] if o0 else 0.0
    nets = []
    print('\n[1] open(H) = a*H + (b/2)*H^2, empty blocks')
    fits = {}
    for name, pts in (('stage A (3 pts)', sa), ('r3 (%d pts)' % len(rr), rr)):
        if len(pts) >= 2:
            a, c = fit(pts); fits[name] = (a, c)
            print('  %-14s a=%.4f ms b=%.4e ms  net H=129600: a-term %.0f s + b-term %.0f s = %s' % (name, a * 1e3, 2 * c * 1e3, a * 129600, c * 129600 ** 2, hms(a * 129600 + c * 129600 ** 2)))
            for h, t in pts:
                print('      H=%6d meas %8.2f s  fit %8.2f s' % (h, t, a * h + c * h * h))
    pair_fits = []
    for pts in (rr,):
        for i in range(len(pts) - 1):
            a, c = two_point(pts[i], pts[i + 1]); pair_fits.append((pts[i][0], pts[i + 1][0], a, c))
            print('  two-point %5d-%5d: a=%.4f ms b=%.4e ms -> net %s' % (pts[i][0], pts[i + 1][0], a * 1e3, 2 * c * 1e3, hms(a * 129600 + c * 129600 ** 2)))
    nets += [a * 129600 + c * 129600 ** 2 for a, c in fits.values()] + [a * 129600 + c * 129600 ** 2 for _, _, a, c in pair_fits[-3:]]
    if nets:
        print('  network empty-block open range (LS fits and the three highest two-point fits): %.0f-%.0f min' % (min(nets) / 60, max(nets) / 60))
    a_r3, c_r3 = fits.get('r3 (%d pts)' % len(rr), fits.get('stage A (3 pts)'))
    bterm_dev = c_r3 * 20000 ** 2; bterm_net = c_r3 * 129600 ** 2
    print('  b-term (r3 LS): devnet %.0f s, network %.0f s' % (bterm_dev, bterm_net))

    # ---- 2. split attribution ----
    sp = lines(P('split.log'), 'JM-SPLIT')
    if sp:
        mids = []; ys = []; tot = 0.0
        for d in sp:
            lo, hi = map(int, d['heights'].split('..')); mids.append((lo + hi) / 2); ys.append(d['insertMs'] + d['retainMs'])
            tot += (d['validateMs'] + d['insertMs'] + d['retainMs']) * (hi - lo + 1) / 1e3
        n = len(mids); mx = sum(mids) / n; my = sum(ys) / n
        slope = sum((x - mx) * (y - my) for x, y in zip(mids, ys)) / sum((x - mx) ** 2 for x in mids)
        print('\n[2] JM-SPLIT (bare-chain replay, %d buckets): insert+retain slope %.4e ms/height; vs r3 fitted b %.4e ms -> %.0f%% attributed' % (n, slope, 2 * c_r3 * 1e3, 100 * slope / (2 * c_r3 * 1e3)))
        print('    first/last bucket: validate %.3f/%.3f insert %.3f/%.3f retain %.3f/%.3f ms' % (sp[0]['validateMs'], sp[-1]['validateMs'], sp[0]['insertMs'], sp[-1]['insertMs'], sp[0]['retainMs'], sp[-1]['retainMs']))
        top = max(rr) if rr else None
        if top:
            print('    bare replay total over %d buckets = %.1f s vs Node::open at H=%d %.1f s -> %.0f%% of open explained' % (n, tot, top[0], top[1], 100 * tot / top[1]))

    # ---- 3. per gas ----
    ex = lines(P('exec.log'), 'JM-EXEC')
    print('\n[3] JM-EXEC: per-block validate (median) of one-tx full-gas blocks, sorted by net ns/gas')
    emp = next((d for d in ex if d['kind'] == 'empty_fallback'), None)
    jl = next((d for d in ex if d['kind'] == 'jump_loop'), None)
    for d in sorted(ex, key=lambda d: -d['nsPerGasNet']):
        print('  %-28s %8.1f ms  net %6.2f ns/gas  body %5d B  x jump_loop %5.1f' % (d['kind'], d['validateMsMedian'], d['nsPerGasNet'], d['bodyBytes'], d['validateMsMedian'] / jl['validateMsMedian'] if jl else 0))
    worst = max(ex, key=lambda d: d['validateMsMedian'])
    print('  worst measured: %s %.1f ms/block (%.1f ns/gas net), %.0fx jump_loop (r2 compute)' % (worst['kind'], worst['validateMsMedian'], worst['nsPerGasNet'], worst['validateMsMedian'] / jl['validateMsMedian']))

    # ---- 4. replay per record by kind ----
    kind = {d['kind']: d for d in lines(P('replay-kind.log'), 'JM-KIND')}
    print('\n[4] JM-KIND per-record open replay (JM-OPEN0 intercept %.1f ms)' % (o0 * 1e3))
    steady = {}
    for k, d in kind.items():
        steady[k] = (d['openSeconds'] - o0) / d['records']
        print('  %-26s %8.2f ms/record (%.2f steady)  %8.1f B/record' % (k, d['perRecordMillis'], steady[k] * 1e3, d['bytesPerRecord']))

    # ---- 5. state term ----
    st = lines(P('state.log'), 'JM-STATE')
    print('\n[5] JM-STATE: validate of an empty / bn_pair_2 / worst-kind child vs live user state')
    for d in st:
        print('  %-8s h=%4d slots=%6d accts=%6d empty %7.1f pair %7.1f %s %7.1f root %7.1f clone %5.2f ms' % (d['series'], d['height'], d['liveUserSlots'], d['liveUserAccounts'], d['emptyChildValidateMs'], d['pairChildValidateMs'], d['childKind'][:12], d['childValidateMs'], d['stateRootMs'], d['stateCloneMs']))
    both = [d for d in st if d['series'] == 'both']
    syn = lines(P('state-syn.log'), 'JM-STATE-SYN')
    for d in syn:
        print('  synthetic slots=%7d accts=%7d: state_root %8.1f ms clone %6.1f ms' % (d['userSlots'], d['userAccounts'], d['stateRootMs'], d['stateCloneMs']))
    dstate_dev = None; st_net = None
    if both:
        f0, f1 = both[0], both[-1]
        dstate_dev = (f1['emptyChildValidateMs'] - f0['emptyChildValidateMs']) / 1e3
        ratio = (f1['emptyChildValidateMs'] - f0['emptyChildValidateMs']) / max(f1['stateRootMs'] - f0['stateRootMs'], 1e-9)
        cpart = (f1['childValidateMs'] - f1['emptyChildValidateMs']) / max(f0['childValidateMs'] - f0['emptyChildValidateMs'], 1e-9)
        print('  devnet near caps (%d slots, %d accts): state term +%.1f ms per block (validate/root increment ratio %.2f); worst child %.1f ms; its compute part at full / at empty state = %.2f' % (
            f1['liveUserSlots'], f1['liveUserAccounts'], dstate_dev * 1e3, ratio, f1['childValidateMs'], cpart))
        if syn:
            s = syn[-1]
            lo = (s['stateRootMs'] + s['stateCloneMs']) / 1e3; hi = s['stateRootMs'] / 1e3 * max(ratio, 1.0)
            st_net = (lo, max(lo, hi))
            print('  network caps (synthetic %d slots, %d accts): root+clone %.1f s; root x devnet ratio %.1f s -> state term %.1f-%.1f s per block (T_blk 60 s, t_exec 3 s)' % (s['userSlots'], s['userAccounts'], lo, hi, st_net[0], st_net[1]))
    fill = {'devnet': (DEV['SLOT_CAP'] // 359 + DEV['ACCT_CAP'] // 230), 'network': (NET['SLOT_CAP'] // 359 + NET['ACCT_CAP'] // 230)}
    print('  full-gas blocks to fill SLOT_CAP and ACCT_CAP (359 slots / 230 accounts per block): devnet %d, network %d' % (fill['devnet'], fill['network']))

    # ---- 6. open-time bounds ----
    print('\n[6] open-time bounds (projections from measured per-record costs; caps-feasible)')
    e_rec = steady.get('empty')
    worst_kinds = [k for k in steady if k.startswith('modexp')]
    rr_top = {h: t for h, t in rr}
    for prof, P_ in (('devnet', DEV), ('network', NET)):
        H = P_['H_END']; bterm = c_r3 * H * H
        print('  %s H_END=%d (b-term %.0f s, JM-OPEN0 %.2f s):' % (prof, H, bterm, o0))
        if prof == 'devnet' and H in rr_top:
            print('    all empty (measured JM-REPLAY) -> %s' % hms(rr_top[H]))
        else:
            print('    all empty (fit range, [1]) -> %.0f-%.0f min' % (min(nets) / 60, max(nets) / 60))
        for k in ['full_gas_compute', 'full_gas_transfers', 'bn_pair_2', 'kzg_point_eval'] + worst_kinds:
            if k not in steady:
                continue
            per_blk_tx = 380 if k == 'full_gas_transfers' else 1
            n_fit = min(H, P_['TX_CAP'] // per_blk_tx, int(P_['TXBYTES_CAP'] // max(ex_body(ex, k), 1)))
            t = n_fit * steady[k] + (H - n_fit) * (e_rec or 0) + bterm + o0
            print('    %-26s %6d blocks within the caps (+ empty) -> %s' % (k, n_fit, hms(t)))
        k = 'modexp_b8_e256_m8_even'
        if k in steady:
            if prof == 'devnet' and dstate_dev is not None:
                n = H - fill['devnet']
                t = n * (steady[k] + dstate_dev) + bterm + o0
                print('    %s on a state at the devnet caps (+%.0f ms each, after %d fill blocks) -> %s' % (k, dstate_dev * 1e3, fill['devnet'], hms(t)))
            if prof == 'network' and st_net:
                n = H - fill['network']
                for stv in st_net:
                    t = n * (steady[k] + stv) + bterm
                    print('    %s on a state at the network caps (+%.1f s each, after %d fill blocks) -> %s = %.1f days' % (k, stv, fill['network'], hms(t), t / 86400))

    # ---- 7. rebuild by kind, deep reorg, re-fetch ----
    rb = {d['kind']: d['perBlockMillis'] / 1e3 for d in lines(P('rebuild-kind.log'), 'JM-REBUILD-KIND')}
    print('\n[7] JM-REBUILD-KIND per-block genesis rebuild: ' + ', '.join('%s %.1f ms' % (k, v * 1e3) for k, v in rb.items()))
    lr = lines(P('reorg-loaded.log'), 'JM-REORG')
    if lr:
        d = lr[0]; reb = d['firstSideImport']['seconds'] / d['firstSideImport']['rebuilds']
        det = d['adoptingImport']['seconds'] - d['adoptingImport']['rebuilds'] * reb
        print('  loaded reorg (%s, f=%d): first stall %.1f s (%.3f s/rebuild); adopting %.1f s = %d rebuilds (%.1f s) + %.1f s other (restore of %d empty T blocks + pool re-execution of %d detached txs)' % (
            d['kind'], d['forkPointHeight'], d['firstSideImport']['seconds'], reb, d['adoptingImport']['seconds'], d['adoptingImport']['rebuilds'], d['adoptingImport']['rebuilds'] * reb, det, d['adoptingImport']['restoredBlocks'], d['reorgDepth']))
    a_e = 2.4e-3
    for prof, P_ in (('devnet', DEV), ('network', NET)):
        H = P_['H_END']; d = 2048; f = H - d
        print('  %s tip %d, d=%d, f=%d:' % (prof, H, d, f))
        cases = [('empty (JM-REBUILD 2.4 ms)', a_e)] + [(k, v) for k, v in rb.items() if k != 'empty']
        if prof == 'devnet' and dstate_dev is not None and 'modexp_b8_e256_m8_even' in rb:
            cases.append(('modexp_b8_e256_m8_even + devnet state term', rb['modexp_b8_e256_m8_even'] + dstate_dev))
        for name, a in cases:
            lat = 2 * f * a + 2 * d * a
            print('    a=%-44s 2(f+d)a = %s (stalls f*a %.0f s, (f+d)*a %.0f s; + <= 1024 detached txs); re-fetch cycle (f+16)a = %s' % (name, hms(lat), f * a, (f + d) * a, hms((f + 16) * a)))
    # ---- 8. open memory ----
    print('\n[8] JM-OPENMEM-FRESH (peak / steady / transient over journal)')
    for k in ('full_body_max', 'empty', 'full_gas_transfers'):
        rs = []
        for i in (1, 2):
            rs += lines(P('openmem-%s-%d.log' % (k, i)), 'JM-OPENMEM-FRESH')
        for d in rs:
            print('  %-20s journal %10d B records %5d: peak %.3f steady %.3f transient %.3f' % (k, d['journalBytes'], d['records'], d['peakOverJournal'], d['steadyOverJournal'], d['transientOverJournal']))
    # ---- 9. canonical worst-case journal ----
    hdr = 129_601 * 3072; tx = 1 << 33; pr = 129_601 * (31.01 * 256 + 26); fr = 41 * 129_601
    ev_id = (256 + 2 * 129_600) * 8192; ev_blk = 129_601 * 8192; ev_emax = 4 * ev_blk
    print('\n[9] canonical worst-case journal at network caps (GiB): headers %.3f + tx %.3f + parentResult %.3f + framing %.3f' % (hdr / GIB, tx / GIB, pr / GIB, fr / GIB))
    for name, e in (('1 item/block (storage.md inventory)', ev_blk), ('one item per identity ever (resources.rs:98-101; binding)', ev_id), ('E_max per block (not binding)', ev_emax)):
        print('  evidence %-58s %.3f -> total %.2f GiB' % (name, e / GIB, (hdr + tx + pr + fr + e) / GIB))

    # ---- 10/11. round 3b: state-interacting blocks and the at-cap / network state term (J-REV3-1/2/3) ----
    r3b = os.path.join(ev, 'journal-r3b')
    P3B = lambda n: os.path.join(r3b, n)
    cr = lines(P3B('create.log'), 'JM-CREATE')
    if cr:
        print('\n[10] JM-CREATE (r3b): create-heavy block re-execution vs live accounts (J-REV3-1)')
        print('  create-term = create2ChildMs - emptyChildMs (the create-specific cost ON TOP of the (a9) root term).')
        xs = []; ys = []
        for d in cr:
            spec = d['create2ChildMs'] - d['emptyChildMs']; c = max(d['create2Creates'], 1)
            print('  A=%6d  empty %7.1f  create2 %7.1f ms (create-term %7.1f ms, %4d creates, %7.1f us/create)  cold-call %6.1f ms (ctrl)  many-small %7.1f ms / %d txs (%7.1f us/create)' % (
                d['liveUserAccounts'], d['emptyChildMs'], d['create2ChildMs'], spec, d['create2Creates'], spec * 1e3 / c,
                d['coldCallChildMs'], d['manySmallCreateMs'], d['manySmallCreateTxs'], (d['manySmallCreateMs'] - d['emptyChildMs']) * 1e3 / max(d['manySmallCreateTxs'], 1)))
            if d['liveUserAccounts'] > 0:
                xs.append(float(d['liveUserAccounts'])); ys.append(spec * 1e3 / c)  # us/create
        creates = cr[-1]['create2Creates']
        if len(xs) >= 2:
            mx = sum(xs) / len(xs); my = sum(ys) / len(ys)
            k = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs); base = my - k * mx
            print('  LS fit (per create): us/create = %.1f + %.4e * A  (A = live user accounts); the slope IS the current_total O(accounts) scan.' % (base, k))
            for prof, cap in (('devnet', DEV['ACCT_CAP']), ('network', NET['ACCT_CAP'])):
                perc = base + k * cap; blk = perc * creates / 1e6
                print('    %-7s ACCT_CAP %8d: %9.0f us/create x %d creates = %7.2f s/block of current_total scan (create-specific; additive to the root term)' % (prof, cap, perc, creates, blk))
            print('  NOTE the network per-block figure is an extrapolation of an extrapolation: (1) create-term/creates fit linear in A, measured only to A=%d (= %.0f%% of the devnet ACCT_CAP); (2) extended linearly to the network ACCT_CAP (10^6, ~%.0fx beyond the measured range); creates per block (%d) assumed unchanged.' % (
                int(xs[-1]), 100 * xs[-1] / DEV['ACCT_CAP'], NET['ACCT_CAP'] / xs[-1], creates))
    # at-cap devnet state term (J-REV3-3): the (a9) "both" series ended at ~95% of the caps; extend by the measured slopes.
    both2 = [d for d in lines(P('state.log'), 'JM-STATE') if d['series'] == 'both'] if cr else []
    if both2:
        slot_pts = [d for d in both2 if d['liveUserAccounts'] < 1000]  # the slot-fill leg (accounts ~flat)
        if len(slot_pts) >= 2:
            s0, s1 = slot_pts[0], slot_pts[-1]
            per_slot = (s1['emptyChildValidateMs'] - s0['emptyChildValidateMs']) / max(s1['liveUserSlots'] - s0['liveUserSlots'], 1)
            a0, a1 = both2[-2], both2[-1]
            per_acct = (a1['emptyChildValidateMs'] - a0['emptyChildValidateMs']) / max(a1['liveUserAccounts'] - a0['liveUserAccounts'], 1)
            meas = both2[-1]; at_cap = meas['emptyChildValidateMs'] + per_slot * (DEV['SLOT_CAP'] - meas['liveUserSlots']) + per_acct * (DEV['ACCT_CAP'] - meas['liveUserAccounts'])
            print('\n[11] devnet state term at the caps (J-REV3-3): measured empty-child %.1f ms at %d slots (%.0f%% of SLOT_CAP) + %d accts (%.0f%% of ACCT_CAP); slopes ~%.1f us/slot, ~%.1f us/acct -> at-cap empty-child ~%.0f ms (state term ~+%.0f ms vs the %.0f ms at the measured fill: the measured figure is a slight under-estimate).' % (
                meas['emptyChildValidateMs'], meas['liveUserSlots'], 100 * meas['liveUserSlots'] / DEV['SLOT_CAP'], meas['liveUserAccounts'], 100 * meas['liveUserAccounts'] / DEV['ACCT_CAP'],
                per_slot * 1e3, per_acct * 1e3, at_cap, at_cap - meas['emptyChildValidateMs'], meas['emptyChildValidateMs']))


def ex_body(ex, k):
    d = next((x for x in ex if x['kind'] == (k if k != 'full_gas_compute' else 'jump_loop')), None)
    return d['bodyBytes'] if d else 1


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'evidence')
