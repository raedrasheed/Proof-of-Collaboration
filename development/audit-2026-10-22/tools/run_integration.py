#!/usr/bin/env python3
"""Audit-repair integration run: the LP10 suites (prototypes/lp10/run_lp10.py SUITES) plus lp1-node and
the extension release build, on the checked-out commit. Writes a summary with commit, toolchain,
per-suite exit status, counts and timing to development/audit-2026-10-22/evidence/integration.json and
full logs to the directory given by --logs (default: a temporary directory; logs are not committed).

usage: python3 development/audit-2026-10-22/tools/run_integration.py [--logs DIR] [--only a,b] [--skip a,b]
lp1-node's store_journal is reported separately: it is Windows-only (UnsupportedPlatform elsewhere)."""
import importlib.util, json, os, re, subprocess, sys, tempfile, time
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
spec = importlib.util.spec_from_file_location("run_lp10", os.path.join(ROOT, "prototypes", "lp10", "run_lp10.py"))
lp10 = importlib.util.module_from_spec(spec); spec.loader.exec_module(lp10)
P = lambda *x: os.path.join(ROOT, "prototypes", *x)
SUITES = [("lp1-node-tests", P("lp1-node"), ["cargo", "test", "--offline", "--no-fail-fast"], 1800),
          ("ext-build", P("pocol-extension"), ["node", "build.mjs"], 300)] + lp10.SUITES

def main():
    a = sys.argv[1:]
    logs = a[a.index("--logs") + 1] if "--logs" in a else tempfile.mkdtemp(prefix="pocol-integration-")
    only = set(a[a.index("--only") + 1].split(",")) if "--only" in a else None
    skip = set(a[a.index("--skip") + 1].split(",")) if "--skip" in a else set()
    os.makedirs(logs, exist_ok=True)
    git = lambda *x: subprocess.run(["git", "-C", ROOT, *x], capture_output=True, text=True).stdout.strip()
    ev = {"commit": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain")), "host": lp10.platform.platform(),
          "toolchain": {"cargo": lp10.version(["cargo", "--version"]), "rustc": lp10.version(["rustc", "--version"]), "node": lp10.version(["node", "--version"]), "python": lp10.platform.python_version()},
          "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "logs": logs, "suites": []}
    ok_all = True
    for name, cwd, cmd, tmo in SUITES:
        if (only and name not in only) or name in skip: continue
        t = time.time(); print(f"== {name}: {' '.join(cmd)}", flush=True)
        try: r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=tmo); code, out = r.returncode, r.stdout + r.stderr
        except subprocess.TimeoutExpired as e: code, out = -1, (e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")) + "\nTIMEOUT"
        open(os.path.join(logs, f"{name}.log"), "w").write(out)
        s = {"suite": name, "cmd": " ".join(cmd), "exit": code, "seconds": round(time.time() - t, 1), "summary": lp10.summarize(name, out)}
        if name == "lp1-node-tests":
            # Separate the platform-blocked binary from the rest.
            blocks = re.split(r"\n\s+Running ", out); blocked = [b for b in blocks if b.startswith("tests/store_journal.rs")]
            s["blockedByPlatform"] = {"binary": "tests/store_journal.rs", "unsupportedPlatform": out.count("UnsupportedPlatform(") , "result": re.findall(r"test result: \w+\. \d+ passed; \d+ failed", blocked[0])[0] if blocked else None}
            others = [b for b in blocks if not b.startswith("tests/store_journal.rs")]
            rs = [m for b in others for m in re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", b)]
            s["summaryExcludingBlocked"] = {"passed": sum(int(x[1]) for x in rs), "failed": sum(int(x[2]) for x in rs)}
            s["pass"] = s["summaryExcludingBlocked"]["failed"] == 0 and len(rs) > 0
        else: s["pass"] = code == 0
        ev["suites"].append(s); ok_all &= s["pass"]
        print(f"   exit={code} {s['seconds']}s {json.dumps(s.get('summaryExcludingBlocked', s['summary']))[:300]}", flush=True)
    ev["result"] = "PASS" if ok_all else "FAIL"; ev["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = os.path.join(ROOT, "development", "audit-2026-10-22", "evidence", "integration.json")
    prev = json.load(open(out)) if os.path.exists(out) else {"runs": []}
    prev["runs"].append(ev); json.dump(prev, open(out, "w"), indent=1)
    print(json.dumps({"result": ev["result"], "suites": [(s["suite"], s["exit"], s["pass"]) for s in ev["suites"]]}))
    return 0 if ok_all else 1

if __name__ == "__main__":
    sys.exit(main())
