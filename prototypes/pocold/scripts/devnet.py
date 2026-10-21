#!/usr/bin/env python3
"""Local PoCol devnet launcher (LP10). Starts N pocold processes on loopback.

usage: devnet.py init  WORK --miners a,b,c [init-devnet flags...]
       devnet.py start WORK [--stop-at H] [--log]
       devnet.py stop  WORK
       devnet.py status WORK
       devnet.py rpc   WORK NODE METHOD [JSON_PARAMS]
Ports: p2p 30300+i, rpc 8540+i (i = node index). Data in WORK/data/<label>.
"""
import json, os, signal, subprocess, sys, time, urllib.request
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("POCOLD", os.path.join(ROOT, "target", "release", "pocold"))

def labels(work): return [m["label"] for m in json.load(open(os.path.join(work, "net", "devnet.json")))["miners_order"]]

def rpc(port, method, params=None, timeout=10):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        v = json.load(r)
    if "error" in v: raise RuntimeError(v["error"])
    return v["result"]

def init(work, miners, extra):
    os.makedirs(work, exist_ok=True)
    out = subprocess.run([BIN, "init-devnet", "--out", os.path.join(work, "net"), "--miners", miners] + extra, check=True, capture_output=True, text=True).stdout
    info = json.load(open(os.path.join(work, "net", "devnet.json")))
    info["miners_order"] = [{"label": l} for l in miners.split(",")]
    json.dump(info, open(os.path.join(work, "net", "devnet.json"), "w"), indent=1)
    print(out)

def start(work, stop_at=None, log=False, only=None):
    ls = labels(work); procs = {}
    for i, l in enumerate(ls):
        if only and l not in only: continue
        peers = sum([["--peer", f"127.0.0.1:{30300+j}"] for j in range(len(ls)) if j != i], [])
        cmd = [BIN, "run", "--network", os.path.join(work, "net"), "--data", os.path.join(work, "data", l), "--name", l, "--miner", l,
               "--listen", f"127.0.0.1:{30300+i}", "--rpc", f"127.0.0.1:{8540+i}"] + peers
        if stop_at: cmd += ["--stop-at", str(stop_at)]
        if log: cmd += ["--log"]
        logf = open(os.path.join(work, f"{l}.log"), "ab")
        p = subprocess.Popen(cmd, stdout=logf, stderr=logf, start_new_session=True)
        procs[l] = p.pid
    pidfile = os.path.join(work, "pids.json")
    old = json.load(open(pidfile)) if os.path.exists(pidfile) else {}
    old.update(procs); json.dump(old, open(pidfile, "w"))
    return procs

def stop(work, only=None, sig=signal.SIGTERM):
    pidfile = os.path.join(work, "pids.json")
    if not os.path.exists(pidfile): return
    pids = json.load(open(pidfile))
    for l, pid in list(pids.items()):
        if only and l not in only: continue
        try: os.kill(pid, sig)
        except ProcessLookupError: pass
        pids.pop(l)
    json.dump(pids, open(pidfile, "w"))

def status(work):
    out = {}
    for i, l in enumerate(labels(work)):
        try: s = rpc(8540+i, "pocol_status"); out[l] = {"height": s["head"]["height"], "hash": s["head"]["hash"][:14], "peers": len(s["peers"]), "prod": s["production"], "stats": s["stats"]}
        except Exception as e: out[l] = {"down": str(e)[:60]}
    return out

if __name__ == "__main__":
    a = sys.argv
    if a[1] == "init": init(a[2], a[a.index("--miners")+1], [x for x in a[3:] if x not in ("--miners", a[a.index("--miners")+1])])
    elif a[1] == "start": print(start(a[2], int(a[a.index("--stop-at")+1]) if "--stop-at" in a else None, "--log" in a))
    elif a[1] == "stop": stop(a[2])
    elif a[1] == "status": print(json.dumps(status(a[2]), indent=1))
    elif a[1] == "rpc":
        i = labels(a[2]).index(a[3]); print(json.dumps(rpc(8540+i, a[4], json.loads(a[5]) if len(a) > 5 else []), indent=1))
