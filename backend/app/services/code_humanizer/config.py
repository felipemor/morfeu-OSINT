"""
Project Memory and Configuration Manager (.code-humanizer.json)
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "1.0.0",
    "mode": "standard",  # safe, standard, aggressive
    "preserveFormatting": True,
    "visualRegression": True,
    "removeRedundantComments": True,
    "semanticHtml": True,
    "extractReactComponents": True,
    "maxRisk": "medium",  # low, medium, high
    "excludePatterns": [
        "node_modules",
        ".git",
        ".next",
        "dist",
        "build",
        ".venv",
        "__pycache__",
        "*.min.js",
        "*.min.css"
    ],
    "designSystem": {
        "framework": "auto",  # auto, tailwind, bootstrap, mui, chakra, css_modules
        "customClasses": []
    },
    "metricsThresholds": {
        "minQualityScore": 85,
        "maxCyclomaticComplexity": 15,
        "maxFileLines": 500
    }
}


class HumanizerConfigManager:
    """Manages reading, persisting and validating .code-humanizer.json"""

    CONFIG_FILENAME = ".code-humanizer.json"

    @classmethod
    def get_config_path(cls, project_root: str) -> Path:
        return Path(project_root) / cls.CONFIG_FILENAME

    @classmethod
    def load_config(cls, project_root: str) -> Dict[str, Any]:
        path = cls.get_config_path(project_root)
        if not path.exists():
            return DEFAULT_CONFIG.copy()
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                merged = DEFAULT_CONFIG.copy()
                merged.update(data)
                return merged
        except Exception:
            return DEFAULT_CONFIG.copy()

    @classmethod
    def save_config(cls, project_root: str, config: Dict[str, Any]) -> bool:
        path = cls.get_config_path(project_root)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False
