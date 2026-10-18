"""Start all nine backend processes. Stop them together with Ctrl+C."""
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
SERVICES = {'part2': ('logs', 'users', 'notifications'),
            'part1': ('assets', 'threats', 'vulnerabilities'),
            'part3': ('incidents', 'reports', 'playbooks')}


def main():
    if len(os.environ.get('SERVICE_SECRET', '')) < 32:
        raise SystemExit('Set SERVICE_SECRET to the same random value of at least 32 characters for this launcher and the bootstrap CLI.')
    for part in SERVICES:
        if not (ROOT / part / 'app.py').exists():
            raise SystemExit(f'Missing {part}/app.py. Extract all three personal ZIPs beside common/ first.')
    processes = []
    try:
        for part, names in SERVICES.items():
            for name in names:
                processes.append(subprocess.Popen([sys.executable, '-m', part + '.app', name], cwd=ROOT))
        print('Starting all nine services. Use Postman after the ports are listening. Ctrl+C stops all services.', flush=True)
        while True:
            if any(process.poll() is not None for process in processes):
                raise SystemExit('A service exited. Check its output (including whether a port is already in use).')
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
