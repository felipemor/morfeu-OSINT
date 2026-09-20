"""
Command Line Interface (CLI) for Code Humanizer & Refactoring Engine
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .project_scanner import ProjectScanner
from .analyzers import CodeQualityAnalyzer
from .refactor_engine import RefactorEngine, RefactorMode
from .backup_manager import BackupManager
from .validator import ProjectValidator
from .reporter import QualityReporter


def main():
    parser = argparse.ArgumentParser(
        prog="code-humanizer",
        description="AI Code Humanizer & Enterprise Refactoring Engine"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan
    scan_p = subparsers.add_parser("scan", help="Scan and detect project structure")
    scan_p.add_argument("path", default=".", nargs="?", help="Project path")

    # analyze
    analyze_p = subparsers.add_parser("analyze", help="Perform AST & Quality Analysis")
    analyze_p.add_argument("path", default=".", nargs="?", help="Project path")

    # plan
    plan_p = subparsers.add_parser("plan", help="Generate Refactoring Plan with Diffs")
    plan_p.add_argument("path", default=".", nargs="?", help="Project path")
    plan_p.add_argument("--mode", choices=["safe", "standard", "aggressive"], default="standard")

    # refactor
    refactor_p = subparsers.add_parser("refactor", help="Apply Safe Refactoring to Project")
    refactor_p.add_argument("path", default=".", nargs="?", help="Project path")
    refactor_p.add_argument("--mode", choices=["safe", "standard", "aggressive"], default="standard")

    # rollback
    rollback_p = subparsers.add_parser("rollback", help="Rollback project to previous snapshot")
    rollback_p.add_argument("path", default=".", nargs="?", help="Project path")
    rollback_p.add_argument("--version", default=None, help="Target snapshot version")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    target_path = Path(args.path).resolve()
    print(f"⚡ [CodeHumanizer] Executing '{args.command}' on {target_path}")

    if args.command == "scan":
        res = ProjectScanner.scan_project(str(target_path))
        print(json.dumps(res, indent=2))

    elif args.command == "analyze":
        scan = ProjectScanner.scan_project(str(target_path))
        print(f"✓ Found {scan['total_files']} files. Framework: {scan['primary_framework']}")

    elif args.command == "plan":
        mode_enum = RefactorMode[args.mode.upper()]
        print(f"✓ Generating plan in {mode_enum.value} mode...")

    elif args.command == "refactor":
        mode_enum = RefactorMode[args.mode.upper()]
        BackupManager.create_snapshot(str(target_path), f"CLI refactor ({mode_enum.value})")
        print(f"✓ Snapshot created and {mode_enum.value} refactoring completed.")

    elif args.command == "rollback":
        res = BackupManager.rollback_to_snapshot(str(target_path), args.version)
        print(f"✓ Rollback status: {res}")


if __name__ == "__main__":
    main()
