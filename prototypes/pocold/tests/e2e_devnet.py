#!/usr/bin/env python3
"""LP5/LP7 end-to-end devnet test with real pocold processes on loopback.

Gates exercised (LOCAL-DEVNET-PLAN.md LP5/LP7):
  * >=100 freshly produced H-full blocks from a fresh genesis across 3 nodes
  * late join (node c starts after height 15) and sync
  * partition: c isolated mines a minority branch; heal -> c reorganizes to the
    heavier branch (D133) and all nodes converge
  * SIGKILL crash of node b during production, restart from its journal
  * malicious peer: wrong-network Hello, garbage frames, invalid block body
  * user transactions submitted over RPC are included and their receipts match
  * convergence: identical canonical hash, stateRoot and receiptsRoot at every
    height on every node; full restart replays to the same head
Exit status 0 only if every check passes.
"""
import json, os, shutil, signal, socket, struct, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import devnet as dn

def wait(pred, timeout, what):
    t = time.time()
    while time.time() - t < timeout:
        try:
            if pred(): return True
        except Exception: pass
        time.sleep(0.5)
    raise AssertionError(f"timeout waiting for {what}")

def h(i, work): return dn.rpc(8540 + i, "pocol_status")["head"]["height"]

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

def main():
    work = tempfile.mkdtemp(prefix="pocol-e2e-")
    checks = []
    def ok(name, cond, detail=""):
        checks.append((name, bool(cond), detail)); print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail else ""), flush=True)
        if not cond: raise AssertionError(name)
    try:
        dn.init(work, "a,b,c", ["--t-blk", "2", "--tau", "20", "--c", "8", "--d-att", "41", "--fb-wait", "3", "--work-bits", "15"])
        info = json.load(open(os.path.join(work, "net", "devnet.json")))
        dn.start(work, log=True, only=["a", "b"])
        wait(lambda: h(0, work) >= 15 and h(1, work) >= 15, 120, "a,b reach 15")
        ok("two nodes produce blocks from fresh genesis", True, f"a={h(0,work)} b={h(1,work)}")
        # Late join.
        dn.start(work, log=True, only=["c"])
        wait(lambda: h(2, work) >= h(0, work) - 1 >= 15, 90, "c syncs")
        ok("late-joining node c syncs to the head", True, f"c={h(2,work)}")
        # Transactions over RPC (alice -> bob), via node a.
        alice = next(x for x in info["accounts"] if x["label"] == "alice"); bob = next(x for x in info["accounts"] if x["label"] == "bob")
        txs = []
        sign = subprocess.run([os.path.join(ROOT, "target", "release", "pocol-sign"), "--chain-id", str(info["chainId"]), "--account", "alice", "--to", bob["address"], "--value", "1000", "--count", "5"],
                              capture_output=True, text=True, check=True).stdout.split()
        for raw in sign: txs.append(dn.rpc(8540, "eth_sendRawTransaction", [raw]))
        def receipts_ok():
            return all(dn.rpc(8540 + i, "eth_getTransactionReceipt", [t]) not in (None,) for t in txs for i in range(3))
        wait(receipts_ok, 90, "tx receipts on all nodes")
        def same_receipts():
            rs = [dn.rpc(8540 + i, "eth_getTransactionReceipt", [txs[-1]]) for i in range(3)]
            return all(r == rs[0] for r in rs)
        try: wait(same_receipts, 60, "receipts converge")
        except AssertionError: pass
        rs = [dn.rpc(8540 + i, "eth_getTransactionReceipt", [txs[-1]]) for i in range(3)]
        if not all(r == rs[0] for r in rs): print(json.dumps(rs, indent=1))
        ok("user transactions included; receipts identical on all nodes", all(r == rs[0] for r in rs) and rs[0]["status"] == "0x1", rs[0]["blockNumber"])
        bal = int(dn.rpc(8541, "eth_getBalance", [bob["address"], "latest"]), 16)
        ok("transfer value applied", bal == 10**24 + 5000, str(bal))
        # Malicious peer against node a.
        s = socket.create_connection(("127.0.0.1", 30300)); s.sendall(frame(b"\xff\xfe garbage")); time.sleep(0.5)
        try: s.settimeout(2); got = s.recv(1)
        except Exception: got = b""
        s.close()
        s = socket.create_connection(("127.0.0.1", 30300))
        hello = rlp_list([uint(0), uint(1), rlp_bytes(b"\x01" * 32), rlp_bytes(b"\x02" * 32), uint(5), rlp_bytes(b"evil")])
        s.sendall(frame(hello)); time.sleep(0.5); s.close()
        # Invalid block: real header bytes with a corrupted state root -> blockReject, node keeps running.
        blk = dn.rpc(8540, "pocol_getBlockRlp", ["latest"])
        hdr = bytearray(bytes.fromhex(blk["header"][2:])); hdr[200] ^= 0xff
        s = socket.create_connection(("127.0.0.1", 30300)); s.sendall(frame(rlp_list([uint(1), rlp_bytes(bytes(hdr)), rlp_bytes(bytes.fromhex(blk["body"][2:]))]))); time.sleep(1); s.close()
        before = h(0, work); wait(lambda: h(0, work) > before, 60, "a keeps producing after malicious input")
        ok("malicious frames/Hello/invalid block do not stop node a", True, f"rejects={len(dn.rpc(8540,'pocol_getRejects'))}")
        # Partition: isolate c (restart without peers and without a listener).
        base_c = h(2, work)
        dn.stop(work, only=["c"]); time.sleep(1)
        ci = 2
        p = subprocess.Popen([dn.BIN, "run", "--network", os.path.join(work, "net"), "--data", os.path.join(work, "data", "c"), "--name", "c", "--miner", "c", "--rpc", "127.0.0.1:8542", "--log"],
                             stdout=open(os.path.join(work, "c-isolated.log"), "ab"), stderr=subprocess.STDOUT, start_new_session=True)
        wait(lambda: h(2, work) >= base_c + 2, 120, "isolated c builds a minority branch")
        c_tip = dn.rpc(8542, "pocol_status")["head"]
        time.sleep(8)
        ab_tip = dn.rpc(8540, "pocol_status")["head"]
        ok("partition: branches diverge", c_tip["hash"] != ab_tip["hash"], f"c={c_tip['height']} ab={ab_tip['height']}")
        os.killpg(p.pid, signal.SIGTERM); p.wait()
        dn.start(work, log=True, only=["c"])
        wait(lambda: dn.rpc(8542, "pocol_status")["head"]["hash"] == dn.rpc(8540, "pocol_status")["head"]["hash"], 120, "heal convergence")
        ok("heal: c reorganizes to the heavier branch", dn.rpc(8542, "pocol_status")["stats"]["reorgs"] >= 1)
        # Crash: SIGKILL b mid-production, restart from its journal.
        os.kill(json.load(open(os.path.join(work, "pids.json")))["b"], signal.SIGKILL); time.sleep(2)
        dn.stop(work, only=["b"]); dn.start(work, log=True, only=["b"])
        wait(lambda: abs(h(1, work) - h(0, work)) <= 1, 90, "b recovers")
        ok("SIGKILL crash: b restarts from its journal and rejoins", True, f"b={h(1,work)}")
        # Reach >= 100 blocks.
        wait(lambda: min(h(i, work) for i in range(3)) >= 100, 400, "100 blocks on all nodes")
        # Convergence on every height of the confirmed common prefix (>= 100). Equal-work tip forks
        # (simultaneous seals while ASERT is easy after the partition/crash) resolve by D133 as soon
        # as one branch is extended first, so the very tip is compared only once it is CONFIRM deep.
        CONFIRM = 6
        def common_top():
            top = min(h(i, work) for i in range(3)) - CONFIRM
            if top < 100: return None
            return top if len({dn.rpc(8540 + i, "eth_getBlockByNumber", [hex(top), False])["hash"] for i in range(3)}) == 1 else None
        wait(lambda: common_top() is not None, 300, "confirmed common prefix >= 100")
        top = common_top() or min(h(i, work) for i in range(3)) - CONFIRM
        mism = []
        for n in range(1, top + 1):
            bs = [dn.rpc(8540 + i, "eth_getBlockByNumber", [hex(n), False]) for i in range(3)]
            if not all((b["hash"], b["stateRoot"], b["receiptsRoot"]) == (bs[0]["hash"], bs[0]["stateRoot"], bs[0]["receiptsRoot"]) for b in bs): mism.append(n)
        ok(f"identical canonical hash/stateRoot/receiptsRoot at heights 1..{top} on 3 nodes", not mism, str(mism[:5]))
        stats = {l: dn.rpc(8540 + i, "pocol_status")["stats"] for i, l in enumerate("abc")}
        ok("every miner produced blocks", all(s["mined"] > 0 for s in stats.values()), json.dumps({k: v["mined"] for k, v in stats.items()}))
        signed = sum(1 for n in range(1, top + 1) if dn.rpc(8540, "eth_getBlockByNumber", [hex(n), False])["pocol"]["signed"])
        ok("signed and fallback templates both occur", 0 < signed < top, f"signed={signed}/{top}")
        # Full restart: deterministic replay. Each journal is replayed by a fresh process with no
        # peers and no miner; the replayed canonical chain must contain the live head observed
        # before the stop (a block imported between that read and SIGTERM may extend it), with the
        # same stateRoot/receiptsRoot, and two independent replays must agree byte-for-byte.
        live = {}
        for i, l in enumerate("abc"):
            hd = dn.rpc(8540 + i, "pocol_status")["head"]; b = dn.rpc(8540 + i, "eth_getBlockByNumber", [hex(hd["height"]), False])
            live[l] = (hd["height"], b["hash"], b["stateRoot"], b["receiptsRoot"])
        dn.stop(work); time.sleep(2)
        for i, l in enumerate("abc"):
            port = 8540 + i
            rp = subprocess.Popen([dn.BIN, "run", "--network", os.path.join(work, "net"), "--data", os.path.join(work, "data", l), "--name", l + "-replay", "--rpc", f"127.0.0.1:{port}"],
                                  stdout=open(os.path.join(work, f"{l}-replay.log"), "ab"), stderr=subprocess.STDOUT, start_new_session=True)
            try:
                wait(lambda: dn.rpc(port, "pocol_status") is not None, 60, f"replay {l}")
                hgt, hsh, sr, rr = live[l]; b = dn.rpc(port, "eth_getBlockByNumber", [hex(hgt), False])
                rhead = dn.rpc(port, "pocol_status")["head"]
                ok(f"replay of {l} reproduces its live head h={hgt} (hash/stateRoot/receiptsRoot)", (b["hash"], b["stateRoot"], b["receiptsRoot"]) == (hsh, sr, rr), f"replayed head h={rhead['height']}")
            finally:
                os.killpg(rp.pid, signal.SIGTERM); rp.wait()
            st1 = subprocess.run([dn.BIN, "status", "--network", os.path.join(work, "net"), "--data", os.path.join(work, "data", l)], capture_output=True, text=True, check=True).stdout
            st2 = subprocess.run([dn.BIN, "status", "--network", os.path.join(work, "net"), "--data", os.path.join(work, "data", l)], capture_output=True, text=True, check=True).stdout
            ok(f"two independent replays of {l} agree", json.loads(st1)["head"] == json.loads(st2)["head"] and json.loads(st1)["head"]["hash"] == rhead["hash"], json.loads(st1)["head"]["hash"][:14])
        print(json.dumps({"result": "PASS", "checks": len(checks), "work": work}))
        return 0
    except Exception as e:
        print(json.dumps({"result": "FAIL", "error": str(e), "checks": [c[0] for c in checks if c[1]], "work": work}))
        return 1
    finally:
        dn.stop(work)

if __name__ == "__main__":
    sys.exit(main())
