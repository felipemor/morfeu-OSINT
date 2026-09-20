"""
AI Code Humanizer & Refactoring Engine (Code Quality & Refactoring Engine)
"""

from .project_scanner import ProjectScanner
from .ast_parsers import ASTParserRegistry
from .analyzers import (
    CodeQualityAnalyzer,
    ComplexityAnalyzer,
    DuplicationAnalyzer,
    DeadCodeAnalyzer,
    SemanticAnalyzer,
    NamingAnalyzer,
    MaintainabilityPatternAnalyzer,
    AccessibilityAnalyzer,
    SecurityAnalyzer,
)
from .refactor_engine import RefactorEngine, RefactorMode
from .backup_manager import BackupManager
from .validator import ProjectValidator
from .reporter import QualityReporter
from .config import HumanizerConfigManager

__all__ = [
    "ProjectScanner",
    "ASTParserRegistry",
    "CodeQualityAnalyzer",
    "ComplexityAnalyzer",
    "DuplicationAnalyzer",
    "DeadCodeAnalyzer",
    "SemanticAnalyzer",
    "NamingAnalyzer",
    "MaintainabilityPatternAnalyzer",
    "AccessibilityAnalyzer",
    "SecurityAnalyzer",
    "RefactorEngine",
    "RefactorMode",
    "BackupManager",
    "ProjectValidator",
    "QualityReporter",
    "HumanizerConfigManager",
]
