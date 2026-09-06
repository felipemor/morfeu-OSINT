#!/usr/bin/env python3
import sys
import subprocess
import os

# Thresholds in Bytes
WARNING_25MB = 25 * 1024 * 1024
BLOCK_50MB = 50 * 1024 * 1024
BLOCK_100MB = 100 * 1024 * 1024

GIT_PATH = r'C:\Users\loren\AppData\Local\Programs\Git\cmd\git.exe' if os.name == 'nt' else 'git'

def check_staged_files():
    try:
        res = subprocess.run(
            [GIT_PATH, 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
            capture_output=True,
            text=True,
            check=True
        )
    except Exception as e:
        print(f"[LARGE-FILE-CHECK] Unable to execute git diff: {e}")
        return 0

    files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
    if not files:
        return 0

    blocked = False
    for rel_path in files:
        if not os.path.exists(rel_path):
            continue

        size = os.path.getsize(rel_path)
        size_mb = size / (1024 * 1024)

        if size >= BLOCK_100MB:
            print(f"\033[91m[ERROR] CRITICAL: '{rel_path}' is {size_mb:.2f} MB! Exceeds GitHub hard limit (100 MB). Commit BLOCKED.\033[0m")
            blocked = True
        elif size >= BLOCK_50MB:
            print(f"\033[91m[ERROR] '{rel_path}' is {size_mb:.2f} MB! Exceeds repository threshold (50 MB). Commit BLOCKED.\033[0m")
            blocked = True
        elif size >= WARNING_25MB:
            print(f"\033[93m[WARNING] '{rel_path}' is {size_mb:.2f} MB! Exceeds recommended threshold (25 MB).\033[0m")

    if blocked:
        print("\033[91m[REJECTED] Please remove large files from index or configure Git LFS if strictly required.\033[0m")
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(check_staged_files())
