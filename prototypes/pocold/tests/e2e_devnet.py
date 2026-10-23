#!/usr/bin/env python3
"""LP5/LP7 end-to-end devnet test with real pocold processes on loopback.

Gates exercised (LOCAL-DEVNET-PLAN.md LP5/LP7):
  * >=100 freshly produced H-full blocks from a fresh genesis across 3 nodes
  * late join (node c starts after height 15) and sync
  * partition and heal with a known winner (D133, consensus.md §9): c is isolated and mines its
    own branch; a and b extend theirs >= 2 blocks past c's isolated head and are restarted without
    a miner; c mines until its branch is strictly heavier than every a/b tip and is restarted
    without a miner too, so no tip can move. Heal: a and b fetch c's branch by Status sync
    (consensus.md:235) and reorganize; every head is exactly c's tip, no a/b tip is canonical on
    any node, and the reorg counters of a and b moved. A test peer then relays the lighter a/b
    branch to c, which never held it: c stores it and keeps its head (the head is the maximum of
    ≻ whatever the order of arrival, consensus.md:215)
  * SIGKILL crash of node b during production, restart from its journal
  * malicious peer: a garbage frame and a wrong-network Hello close the connection (a well-formed
    Hello does not); a corrupted block sent after a valid Hello is rejected; a keeps producing
  * user transactions submitted over RPC are included and their receipts match
  * convergence: identical canonical hash, stateRoot and receiptsRoot at every
    height on every node; full restart replays to the same head
Every wait is bounded and names what it waited for. Exit status 0 only if every check passes.
POCOLD selects the pocold binary; pocol-sign is taken from the same directory (or POCOL_SIGN).
"""
import contextlib, io, json, os, signal, socket, struct, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import devnet as dn
SIGN = os.environ.get("POCOL_SIGN", os.path.join(os.path.dirname(dn.BIN), "pocol-sign"))
L = "abc"

def waited(pred, timeout):
    t = time.time()
    while time.time() - t < timeout:
        try:
            if pred(): return True
        except Exception: pass
        time.sleep(0.5)
    return False
def wait(pred, timeout, what):
    if not waited(pred, timeout): raise AssertionError(f"timeout waiting for {what}")

def st(i): return dn.rpc(8540 + i, "pocol_status")
def h(i): return st(i)["head"]["height"]
def tip(i): x = st(i)["head"]; return {"hash": x["hash"], "number": x["height"], "work": int(x["totalWork"], 16)}
def canon(i, n): b = dn.rpc(8540 + i, "eth_getBlockByNumber", [hex(n), False]); return b and b["hash"]
def short(t): return f"{t['number']}:{t['hash'][:12]}:w={t['work']:#x}"
def port_open(p):
    with socket.socket() as s: s.settimeout(0.5); return s.connect_ex(("127.0.0.1", p)) == 0

def frame(payload): return struct.pack(">I", len(payload)) + payload
def rlp_bytes(b):
    if len(b) == 1 and b[0] < 0x80: return b
    if len(b) < 56: return bytes([0x80 + len(b)]) + b
    l = len(b).to_bytes((len(b).bit_length() + 7) // 8, "big"); return bytes([0xb7 + len(l)]) + l + b
def rlp_list(items):
    p = b"".join(items)
    if len(p) < 56: return bytes([0xc0 + len(p)]) + p
    l = len(p).to_bytes((len(p).bit_length() + 7) // 8, "big"); return bytes([0xf7 + len(l)]) + l + p
def uint(v): return rlp_bytes(v.to_bytes((v.bit_length() + 7) // 8, "big") if v else b"")
# VA-SPEC wire: Hello = [0, chainId, genesisHash, headHash, height, totalWork (32 B), name]; Block = [1, header, body].
def hello(chain_id, genesis, head, height, work, name): return frame(rlp_list([uint(0), uint(chain_id), rlp_bytes(genesis), rlp_bytes(head), uint(height), rlp_bytes(work.to_bytes(32, "big")), rlp_bytes(name)]))
def block_frame(blk): return frame(rlp_list([uint(1), rlp_bytes(bytes.fromhex(blk["header"][2:])), rlp_bytes(bytes.fromhex(blk["body"][2:]))]))
def closed_by_peer(s, t):
    """Drops what the node sends until it closes the connection: True if it does within t s."""
    end = time.time() + t
    try:
        while time.time() < end:
            s.settimeout(max(0.05, end - time.time()))
            try:
                if not s.recv(65536): return True
            except socket.timeout: return False
    except OSError: return True
    return False

def main():
    busy = [p for p in (30300, 30301, 30302, 8540, 8541, 8542) if port_open(p)]
    if busy: print(json.dumps({"result": "FAIL", "error": f"ports busy {busy}"})); return 1
    work = tempfile.mkdtemp(prefix="pocol-e2e-"); net = os.path.join(work, "net")
    checks = []; procs = {}; mined = {l: 0 for l in L}
    def ok(name, cond, detail=""):
        checks.append((name, bool(cond), detail)); print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail else ""), flush=True)
        if not cond: raise AssertionError(name)
    def run_node(l, miner=True, connect=True):
        # As devnet.py start; isolated (connect=False): no listener and no peers.
        i = L.index(l)
        cmd = [dn.BIN, "run", "--network", net, "--data", os.path.join(work, "data", l), "--name", l, "--rpc", f"127.0.0.1:{8540+i}", "--log"]
        if miner: cmd += ["--miner", l]
        if connect: cmd += ["--listen", f"127.0.0.1:{30300+i}"] + sum([["--peer", f"127.0.0.1:{30300+j}"] for j in range(3) if j != i], [])
        procs[l] = subprocess.Popen(cmd, stdout=open(os.path.join(work, f"{l}.log"), "ab"), stderr=subprocess.STDOUT, start_new_session=True)
        pf = os.path.join(work, "pids.json"); pids = json.load(open(pf)) if os.path.exists(pf) else {}
        pids[l] = procs[l].pid; json.dump(pids, open(pf, "w"))
        wait(lambda: st(i) is not None, 60, f"{l} answers RPC")
    def stop_node(l, sig=signal.SIGTERM):
        # The `mined` counter restarts with its process, so it is added up just before each stop; a
        # block mined after this read is not counted, so the sum can only be low.
        i = L.index(l)
        try: mined[l] += st(i)["stats"]["mined"]
        except Exception: pass
        dn.stop(work, only=[l], sig=sig)
        try: procs.pop(l).wait(30)
        except (KeyError, subprocess.TimeoutExpired): pass
        wait(lambda: not port_open(8540 + i) and not port_open(30300 + i), 30, f"{l} stopped")
    try:
        with contextlib.redirect_stdout(io.StringIO()):  # init-devnet echoes devnet.json
            dn.init(work, "a,b,c", ["--t-blk", "2", "--tau", "20", "--c", "8", "--d-att", "41", "--fb-wait", "3", "--work-bits", "15"])
        info = json.load(open(os.path.join(net, "devnet.json"))); genesis = bytes.fromhex(info["genesisHash"][2:])
        run_node("a"); run_node("b")
        wait(lambda: h(0) >= 15 and h(1) >= 15, 120, "a,b reach 15")
        ok("two nodes produce blocks from fresh genesis", True, f"a={h(0)} b={h(1)}")
        # Late join.
        run_node("c")
        wait(lambda: h(2) >= h(0) - 1 >= 15, 90, "c syncs")
        ok("late-joining node c syncs to the head", True, f"c={h(2)}")
        # Transactions over RPC (alice -> bob), via node a.
        alice = next(x for x in info["accounts"] if x["label"] == "alice"); bob = next(x for x in info["accounts"] if x["label"] == "bob")
        txs = []
        sign = subprocess.run([SIGN, "--chain-id", str(info["chainId"]), "--account", "alice", "--to", bob["address"], "--value", "1000", "--count", "5"],
                              capture_output=True, text=True, check=True).stdout.split()
        for raw in sign: txs.append(dn.rpc(8540, "eth_sendRawTransaction", [raw]))
        def receipts_ok():
            return all(dn.rpc(8540 + i, "eth_getTransactionReceipt", [t]) not in (None,) for t in txs for i in range(3))
        wait(receipts_ok, 90, "tx receipts on all nodes")
        def same_receipts():
            rs = [dn.rpc(8540 + i, "eth_getTransactionReceipt", [txs[-1]]) for i in range(3)]
            return all(r == rs[0] for r in rs)
        waited(same_receipts, 60)
        rs = [dn.rpc(8540 + i, "eth_getTransactionReceipt", [txs[-1]]) for i in range(3)]
        if not all(r == rs[0] for r in rs): print(json.dumps(rs, indent=1))
        ok("user transactions included; receipts identical on all nodes", all(r == rs[0] for r in rs) and rs[0]["status"] == "0x1", rs[0]["blockNumber"])
        bal = int(dn.rpc(8541, "eth_getBalance", [bob["address"], "latest"]), 16)
        ok("transfer value applied", bal == 10**24 + 5000, str(bal))
        # Malicious peer against node a (VA-SPEC: malformed frames and a wrong network close the
        # connection). The control, a well-formed Hello of this network, keeps it open, so a close
        # is attributable to the input; the corrupted block is sent after that Hello, so it reaches
        # validation (before a Hello any other frame closes the connection unread).
        s = socket.create_connection(("127.0.0.1", 30300)); s.sendall(frame(b"\xff\xfe garbage")); garbage = closed_by_peer(s, 5); s.close()
        s = socket.create_connection(("127.0.0.1", 30300)); s.sendall(hello(1, b"\x01" * 32, b"\x02" * 32, 5, 5, b"evil")); wrong = closed_by_peer(s, 5); s.close()
        s = socket.create_connection(("127.0.0.1", 30300)); s.sendall(hello(info["chainId"], genesis, genesis, 0, 0, b"e2e")); kept = not closed_by_peer(s, 2)
        ok("malicious peer: a garbage frame and a wrong-network Hello close the connection; a well-formed Hello does not", garbage and wrong and kept,
           f"garbage closed={garbage} wrong-network closed={wrong} valid kept={kept}")
        rej0 = {json.dumps(r, sort_keys=True) for r in dn.rpc(8540, "pocol_getRejects")}
        n = h(0); blk = dn.rpc(8540, "pocol_getBlockRlp", [hex(n)]); sr = bytes.fromhex(dn.rpc(8540, "eth_getBlockByNumber", [hex(n), False])["stateRoot"][2:])
        hdr = bytearray(bytes.fromhex(blk["header"][2:])); k = hdr.find(sr); hdr[k + 16 if k >= 0 else 200] ^= 0xff  # a stateRoot byte: still decodes, new hash
        s.sendall(frame(rlp_list([uint(1), rlp_bytes(bytes(hdr)), rlp_bytes(bytes.fromhex(blk["body"][2:]))])))
        rejected = waited(lambda: any(json.dumps(r, sort_keys=True) not in rej0 for r in dn.rpc(8540, "pocol_getRejects")), 15); s.close()
        before = h(0); progressed = waited(lambda: h(0) > before, 60)
        ok("malicious peer: a corrupted block after a valid Hello is rejected and a keeps producing", rejected and progressed,
           f"new reject={rejected} rejects={len(dn.rpc(8540, 'pocol_getRejects'))} a {before}->{h(0)}")
        # Partition and heal (D133, consensus.md §9) with a winner fixed before the heal. c is isolated
        # (no listener, no peers) and keeps mining; a and b extend their branch >= 2 blocks past c's
        # isolated head (the fork point is at most that height, so their reorganization is >= 2 deep)
        # and are restarted without a miner; c mines until it is strictly heavier than every a/b tip.
        stop_node("c"); run_node("c", connect=False)
        c0 = h(2)
        wait(lambda: min(h(0), h(1)) >= c0 + 2, 90, "a and b extend their branch 2 blocks past c's isolated head")
        for l in "ab": stop_node(l)
        for l in "ab": run_node(l, miner=False)
        # a and b settle between themselves (two equal-work siblings of one kind may stay apart: that tie is local, D133).
        wait(lambda: tip(0)["work"] == tip(1)["work"], 60, "a and b settle on their branch")
        ab_tips = [tip(0), tip(1)]; w_ab = max(t["work"] for t in ab_tips)
        t0 = time.time(); lead = waited(lambda: tip(2)["work"] > w_ab, 300)
        ok("partition: isolated c builds a branch strictly heavier than the frozen a/b tips", lead, f"c={short(tip(2))} a/b={[short(t) for t in ab_tips]} in {time.time()-t0:.0f}s")
        forks = [next(n for n in range(min(tip(2)["number"], t["number"]), -1, -1) if canon(i, n) == canon(2, n)) for i, t in enumerate(ab_tips)]
        relay = [dn.rpc(8540, "pocol_getBlockRlp", [hex(n)]) for n in range(forks[0] + 1, ab_tips[0]["number"] + 1)]
        reorgs0 = [st(i)["stats"]["reorgs"] for i in (0, 1)]
        # c's miner stops too; c rejoins without one. From here no tip can move: c's tip is the known winner.
        stop_node("c"); run_node("c", miner=False)
        c_tip = tip(2)
        ok("partition: branches diverge; c's tip is strictly heavier and each a/b tip is >= 2 blocks past the fork",
           c_tip["work"] > w_ab and all(c_tip["number"] > f and t["number"] >= f + 2 for f, t in zip(forks, ab_tips)),
           f"c={short(c_tip)} a/b={[short(t) for t in ab_tips]} fork={forks}")
        t0 = time.time(); healed = waited(lambda: all(tip(i)["hash"] == c_tip["hash"] for i in range(3)), 120)
        heads = [tip(i) for i in range(3)]
        ok("heal: every node's head is c's tip (the strictly heavier branch)", healed, f"heads a/b/c={[short(t) for t in heads]} c_tip={short(c_tip)} in {time.time()-t0:.0f}s")
        ok("heal: on every node the canonical block at c's tip height is c's tip", all(canon(i, c_tip["number"]) == c_tip["hash"] for i in range(3)))
        ok("heal: no a/b tip is canonical on any node", all(canon(i, t["number"]) != t["hash"] for t in ab_tips for i in range(3)), f"a/b={[short(t) for t in ab_tips]}")
        reorgs = [st(i)["stats"]["reorgs"] for i in (0, 1)]
        ok("heal: a and b reorganized (their reorg counters moved)", all(r > r0 for r, r0 in zip(reorgs, reorgs0)), f"a/b reorgs {reorgs0} -> {reorgs}")
        # Relay: a test peer (valid Hello, claiming genesis, so no sync session is started with it)
        # delivers the lighter a/b branch, parents first, to c, which never held it.
        s = socket.create_connection(("127.0.0.1", 30302)); s.sendall(hello(info["chainId"], genesis, genesis, 0, 0, b"e2e-relay"))
        for b in relay: s.sendall(block_frame(b))
        stored = waited(lambda: dn.rpc(8542, "eth_getBlockByHash", [ab_tips[0]["hash"], False]) is not None, 60); s.close()
        ok("relay: c stores the lighter a/b branch delivered after the heal", stored, f"{len(relay)} blocks h={forks[0]+1}..{ab_tips[0]['number']}")
        c_now = tip(2)
        ok("relay: c keeps its head and the relayed lighter tip is not canonical (head = maximum of ≻, consensus.md:215)",
           c_now["hash"] == c_tip["hash"] and canon(2, ab_tips[0]["number"]) != ab_tips[0]["hash"], f"c head={short(c_now)}")
        # Every node mines again on the healed chain.
        for l in L: stop_node(l)
        for l in L: run_node(l)
        wait(lambda: min(h(i) for i in range(3)) > c_tip["number"], 120, "production resumes on the healed chain")
        # Crash: SIGKILL b mid-production, restart from its journal.
        stop_node("b", signal.SIGKILL); run_node("b")
        wait(lambda: abs(h(1) - h(0)) <= 1, 90, "b recovers")
        ok("SIGKILL crash: b restarts from its journal and rejoins", True, f"b={h(1)}")
        # Reach >= 100 blocks.
        wait(lambda: min(h(i) for i in range(3)) >= 100, 400, "100 blocks on all nodes")
        # Convergence on every height of the confirmed common prefix (>= 100). Equal-work tip forks
        # (simultaneous seals while ASERT is easy after the partition/crash) resolve by D133 as soon
        # as one branch is extended first, so the very tip is compared only once it is CONFIRM deep.
        CONFIRM = 6
        def common_top():
            top = min(h(i) for i in range(3)) - CONFIRM
            if top < 100: return None
            return top if len({canon(i, top) for i in range(3)}) == 1 else None
        wait(lambda: common_top() is not None, 300, "confirmed common prefix >= 100")
        top = common_top() or min(h(i) for i in range(3)) - CONFIRM
        mism = []
        for n in range(1, top + 1):
            bs = [dn.rpc(8540 + i, "eth_getBlockByNumber", [hex(n), False]) for i in range(3)]
            if not all((b["hash"], b["stateRoot"], b["receiptsRoot"]) == (bs[0]["hash"], bs[0]["stateRoot"], bs[0]["receiptsRoot"]) for b in bs): mism.append(n)
        ok(f"identical canonical hash/stateRoot/receiptsRoot at heights 1..{top} on 3 nodes", not mism, str(mism[:5]))
        # Every miner produced blocks: each process's `mined` counter (own blocks imported) added up
        # over its restarts. Cross-check on the chain: every miner won canonical blocks (winner =
        # owner(nonce)); a and b mine heights 1..15 alone, and c's isolated branch is canonical.
        stats = {l: st(i)["stats"] for i, l in enumerate(L)}
        total = {k: mined[k] + stats[k]["mined"] for k in L}
        ok("every miner produced blocks", all(v > 0 for v in total.values()), json.dumps(total))
        blocks = [dn.rpc(8540, "eth_getBlockByNumber", [hex(n), False]) for n in range(1, top + 1)]
        ids = {m["id"].lower(): m["label"] for m in info["miners"]}
        wins = {l: sum(1 for b in blocks if ids.get(b["miner"].lower()) == l) for l in L}
        ok("every miner won canonical blocks", all(v > 0 for v in wins.values()), json.dumps(wins))
        signed = sum(1 for b in blocks if b["pocol"]["signed"])
        ok("signed and fallback templates both occur", 0 < signed < top, f"signed={signed}/{top}")
        # Full restart: deterministic replay. Each journal is replayed by a fresh process with no
        # peers and no miner; the replayed canonical chain must contain the live head observed
        # before the stop (a block imported between that read and SIGTERM may extend it), with the
        # same stateRoot/receiptsRoot, and two independent replays must agree byte-for-byte.
        live = {}
        for i, l in enumerate(L):
            hd = st(i)["head"]; b = dn.rpc(8540 + i, "eth_getBlockByNumber", [hex(hd["height"]), False])
            live[l] = (hd["height"], b["hash"], b["stateRoot"], b["receiptsRoot"])
        for l in L: stop_node(l)
        for i, l in enumerate(L):
            port = 8540 + i
            rp = subprocess.Popen([dn.BIN, "run", "--network", net, "--data", os.path.join(work, "data", l), "--name", l + "-replay", "--rpc", f"127.0.0.1:{port}"],
                                  stdout=open(os.path.join(work, f"{l}-replay.log"), "ab"), stderr=subprocess.STDOUT, start_new_session=True)
            try:
                wait(lambda: dn.rpc(port, "pocol_status") is not None, 60, f"replay {l}")
                hgt, hsh, sr, rr = live[l]; b = dn.rpc(port, "eth_getBlockByNumber", [hex(hgt), False])
                rhead = dn.rpc(port, "pocol_status")["head"]
                ok(f"replay of {l} reproduces its live head h={hgt} (hash/stateRoot/receiptsRoot)", (b["hash"], b["stateRoot"], b["receiptsRoot"]) == (hsh, sr, rr), f"replayed head h={rhead['height']}")
            finally:
                os.killpg(rp.pid, signal.SIGTERM); rp.wait()
            st1 = subprocess.run([dn.BIN, "status", "--network", net, "--data", os.path.join(work, "data", l)], capture_output=True, text=True, check=True).stdout
            st2 = subprocess.run([dn.BIN, "status", "--network", net, "--data", os.path.join(work, "data", l)], capture_output=True, text=True, check=True).stdout
            ok(f"two independent replays of {l} agree", json.loads(st1)["head"] == json.loads(st2)["head"] and json.loads(st1)["head"]["hash"] == rhead["hash"], json.loads(st1)["head"]["hash"][:14])
        print(json.dumps({"result": "PASS", "checks": len(checks), "work": work}))
        return 0
    except Exception as e:
        print(json.dumps({"result": "FAIL", "error": str(e), "checks": [c[0] for c in checks if c[1]], "work": work}))
        return 1
    finally:
        dn.stop(work)
        for p in procs.values():
            try: os.killpg(p.pid, signal.SIGTERM); p.wait(30)
            except Exception: pass

if __name__ == "__main__":
    sys.exit(main())
