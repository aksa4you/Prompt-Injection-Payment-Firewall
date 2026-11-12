"""Start the whole firewall stack locally: repos 1-4, the demo shop and the dashboard.

    python scripts/run_all.py                 # expects the five repos side by side (see README)
    python scripts/run_all.py --repos-dir ..  # or point at the folder that holds them
    python scripts/run_all.py --attack-run    # start everything, run every scenario, print the table, stop

Ports: 8001 paypal · 8002 detector · 8003 policy · 8004 gateway · 8005 dashboard · 8006 shop
Ctrl+C stops everything.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
ME = HERE.parent

SERVICES = [  # (folder, uvicorn target, port)
    ("1-paypal-authorize-service", "app.main:app", 8001),
    ("2-injection-detector", "app.main:app", 8002),
    ("3-intent-policy-engine", "app.main:app", 8003),
    ("4-agent-gateway", "app.main:app", 8004),
    ("5-demo-redteam-dashboard", "app.dashboard:app", 8005),
    ("5-demo-redteam-dashboard", "app.shop:app", 8006),
]


def find_repo(repos_dir: Path, folder: str) -> Path:
    for candidate in (repos_dir / folder, ME if folder == ME.name else None):
        if candidate and candidate.is_dir():
            return candidate
    raise SystemExit(f"cannot find {folder!r} in {repos_dir}. Unzip all five repos side by side or pass --repos-dir.")


def wait_healthy(port: int, timeout: float = 30.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=1.0).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        if port == 8005:  # the dashboard has no /healthz; the page itself is the check
            try:
                if httpx.get(f"http://127.0.0.1:{port}/api/scenarios", timeout=1.0).status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
        time.sleep(0.3)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repos-dir", default=str(ME.parent), help="folder containing the five repo folders")
    ap.add_argument("--attack-run", action="store_true", help="run all scenarios against the stack, then exit")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    repos_dir = Path(args.repos_dir).resolve()

    procs: list[subprocess.Popen] = []

    def stop(*_: object) -> None:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    signal.signal(signal.SIGTERM, lambda *_: (stop(), sys.exit(0)))
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        for folder, target, port in SERVICES:
            cwd = find_repo(repos_dir, folder)
            procs.append(subprocess.Popen(
                [sys.executable, "-m", "uvicorn", target, "--host", args.host, "--port", str(port), "--log-level", "warning"],
                cwd=cwd, env=env))
        for (folder, target, port) in SERVICES:
            if not wait_healthy(port):
                print(f"!! {folder} ({target}) did not become healthy on :{port}", file=sys.stderr)
                return 1
            print(f"up   :{port}  {folder}  {target}")
        print("\nDashboard: http://127.0.0.1:8005   Shop: http://127.0.0.1:8006\n")

        if args.attack_run:
            sys.path.insert(0, str(ME))
            from app.runner import Runner, render
            from app import pages
            runner = Runner()
            results = [runner.run(s.id, m) for s in pages.SCENARIOS for m in ("unprotected", "protected")]
            print(render(results))
            bad = [r for r in results if r["mode"] == "protected" and not r["passed"]]
            return 1 if bad else 0

        print("Press Ctrl+C to stop.")
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        stop()


if __name__ == "__main__":
    sys.exit(main())
