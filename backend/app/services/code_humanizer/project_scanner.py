"""
Project Scanner, File Classifier & Dependency Analyzer
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class ProjectScanner:
    """Scans and analyzes project layout, frameworks, dependencies and files."""

    SUPPORTED_EXTENSIONS = {
        ".html": "HTML",
        ".htm": "HTML",
        ".css": "CSS",
        ".scss": "SCSS",
        ".sass": "SCSS",
        ".less": "LESS",
        ".js": "JavaScript",
        ".mjs": "JavaScript",
        ".cjs": "JavaScript",
        ".jsx": "JSX",
        ".ts": "TypeScript",
        ".tsx": "TSX",
        ".json": "JSON",
        ".vue": "Vue",
        ".py": "Python",
    }

    IGNORE_DIRS = {
        "node_modules",
        ".git",
        ".next",
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
        ".turbo",
        ".cache",
        "coverage"
    }

    @classmethod
    def scan_project(cls, root_path: str, max_files: int = 400) -> Dict[str, Any]:
        root = Path(root_path)
        if not root.exists():
            return {"error": f"Path not found: {root_path}", "exists": False}

        file_tree = []
        languages_detected: Dict[str, int] = {}
        total_lines = 0
        total_bytes = 0
        config_files: List[str] = []
        dependencies: Dict[str, str] = {}
        scripts_available: Dict[str, str] = {}
        framework_hints: Set[str] = set()
        design_systems: Set[str] = set()

        # Check package.json
        pkg_path = root / "package.json"
        if pkg_path.exists():
            config_files.append("package.json")
            try:
                with open(pkg_path, "r", encoding="utf-8") as f:
                    pkg_data = json.load(f)
                    scripts_available = pkg_data.get("scripts", {})
                    all_deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
                    dependencies = all_deps
                    if "next" in all_deps:
                        framework_hints.add("Next.js")
                    if "react" in all_deps:
                        framework_hints.add("React")
                    if "vue" in all_deps:
                        framework_hints.add("Vue")
                    if "express" in all_deps:
                        framework_hints.add("Express")
                    if "vite" in all_deps:
                        framework_hints.add("Vite")
                    if "tailwindcss" in all_deps:
                        design_systems.add("Tailwind CSS")
                    if "@mui/material" in all_deps or "@material-ui/core" in all_deps:
                        design_systems.add("Material UI")
                    if "@chakra-ui/react" in all_deps:
                        design_systems.add("Chakra UI")
                    if "bootstrap" in all_deps:
                        design_systems.add("Bootstrap")
                    if "shadcn" in str(all_deps) or "@radix-ui" in str(all_deps):
                        design_systems.add("shadcn/ui")
            except Exception:
                pass

        # Check configuration files
        configs_to_check = [
            "tsconfig.json", "next.config.js", "next.config.mjs", "next.config.ts",
            "vite.config.js", "vite.config.ts", "tailwind.config.js", "tailwind.config.ts",
            ".eslintrc.json", ".eslintrc.js", "eslint.config.js", "eslint.config.mjs",
            ".prettierrc", "prettier.config.js", ".editorconfig", ".code-humanizer.json"
        ]
        for cfg in configs_to_check:
            if (root / cfg).exists():
                config_files.append(cfg)
                if "tailwind" in cfg:
                    design_systems.add("Tailwind CSS")
                if "next" in cfg:
                    framework_hints.add("Next.js")
                if "vite" in cfg:
                    framework_hints.add("Vite")

        # Walk project tree
        file_count = 0
        for current_root, dirs, files in os.walk(root):
            # filter out ignored directories
            dirs[:] = [d for d in dirs if d not in cls.IGNORE_DIRS and not d.startswith(".")]

            for file_name in files:
                if file_count >= max_files:
                    break
                file_path = Path(current_root) / file_name
                rel_path = file_path.relative_to(root).as_posix()
                ext = file_path.suffix.lower()

                if ext in cls.SUPPORTED_EXTENSIONS:
                    file_count += 1
                    lang = cls.SUPPORTED_EXTENSIONS[ext]
                    languages_detected[lang] = languages_detected.get(lang, 0) + 1

                    try:
                        size = file_path.stat().st_size
                        total_bytes += size
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            lines = content.count("\n") + 1
                            total_lines += lines

                            # Fast heuristics
                            has_jsx = "<" in content and "/>" in content
                            has_hooks = "useState" in content or "useEffect" in content
                            has_tailwind = "className=" in content and ("flex" in content or "grid" in content)

                            file_tree.append({
                                "path": rel_path,
                                "name": file_name,
                                "extension": ext,
                                "language": lang,
                                "lines": lines,
                                "size_bytes": size,
                                "has_jsx": has_jsx,
                                "has_react_hooks": has_hooks,
                                "has_tailwind": has_tailwind,
                                "category": cls._classify_file_category(rel_path, ext)
                            })
                    except Exception:
                        pass

        if not framework_hints:
            if any(f["has_react_hooks"] or f["has_jsx"] for f in file_tree):
                framework_hints.add("React")
            elif any(f["language"] in ["JavaScript", "TypeScript"] for f in file_tree):
                framework_hints.add("Node.js / Vanilla JS")
            else:
                framework_hints.add("Static Web Project")

        primary_framework = list(framework_hints)[0] if framework_hints else "JavaScript Application"

        return {
            "root_path": str(root.resolve()),
            "project_name": root.name,
            "primary_framework": primary_framework,
            "all_frameworks": list(framework_hints),
            "design_systems": list(design_systems) if design_systems else ["Vanilla CSS / CSS Modules"],
            "config_files": config_files,
            "scripts_available": scripts_available,
            "total_files": len(file_tree),
            "total_lines": total_lines,
            "total_bytes": total_bytes,
            "languages": languages_detected,
            "files": file_tree
        }

    @staticmethod
    def _classify_file_category(rel_path: str, ext: str) -> str:
        p = rel_path.lower()
        if "component" in p:
            return "Component"
        if "page" in p or "app/" in p or "route" in p:
            return "Page / Route"
        if "hook" in p:
            return "Custom Hook"
        if "service" in p or "api" in p:
            return "Service / API Client"
        if "util" in p or "helper" in p or "lib" in p:
            return "Utility / Library"
        if "style" in p or ext in [".css", ".scss", ".sass", ".less"]:
            return "Stylesheet"
        if "test" in p or "spec" in p or "__tests__" in p:
            return "Test Suite"
        if ext == ".json":
            return "Configuration / Data"
        return "Source File"
