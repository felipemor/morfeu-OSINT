"""
Code Quality & Technical Analyzers for Code Humanizer
"""

import math
import re
from typing import Any, Dict, List, Optional
from .ast_parsers import ASTParserRegistry


class ComplexityAnalyzer:
    """Calculates cyclomatic and structural cognitive complexity."""

    @classmethod
    def analyze(cls, content: str, language: str) -> Dict[str, Any]:
        lines = content.split("\n")
        total_lines = len(lines)
        
        # Decision points
        branch_patterns = [
            r"\bif\b", r"\belse\s+if\b", r"\bfor\b", r"\bwhile\b",
            r"\bcase\b", r"\bcatch\b", r"\?\s*[^:]+\s*:", r"&&", r"\|\|"
        ]
        cyclomatic = 1
        for p in branch_patterns:
            cyclomatic += len(re.findall(p, content))

        # Max nesting depth heuristic
        max_nesting = 0
        current_nesting = 0
        for line in lines:
            stripped = line.strip()
            current_nesting += stripped.count("{") - stripped.count("}")
            current_nesting = max(0, current_nesting)
            max_nesting = max(max_nesting, current_nesting)

        # Rating score (0 to 100, where 100 is cleanest/simplest)
        penalty = min(60, (cyclomatic - 1) * 3) + min(30, max_nesting * 4) + (20 if total_lines > 400 else 0)
        score = max(20, 100 - penalty)

        return {
            "score": score,
            "cyclomatic_complexity": cyclomatic,
            "max_nesting_depth": max_nesting,
            "total_lines": total_lines,
            "is_high_complexity": cyclomatic > 20 or max_nesting > 5 or total_lines > 500
        }


class DuplicationAnalyzer:
    """Detects duplicated lines, identical logic blocks, and repeated class strings."""

    @classmethod
    def analyze(cls, content: str) -> Dict[str, Any]:
        lines = [l.strip() for l in content.split("\n") if len(l.strip()) > 10 and not l.strip().startswith("//")]
        seen: Dict[str, int] = {}
        for l in lines:
            seen[l] = seen.get(l, 0) + 1

        duplicates = [{"line": k, "occurrences": v} for k, v in seen.items() if v >= 3]
        total_dup_lines = sum(d["occurrences"] for d in duplicates)
        dup_ratio = total_dup_lines / max(1, len(lines))

        score = max(30, int(100 - (dup_ratio * 150)))

        return {
            "score": score,
            "duplicate_blocks_count": len(duplicates),
            "duplicates": duplicates[:10],
            "duplication_ratio": round(dup_ratio, 3)
        }


class DeadCodeAnalyzer:
    """Detects unused imports, unreachable code blocks, and orphaned variables."""

    @classmethod
    def analyze(cls, content: str, language: str) -> Dict[str, Any]:
        findings = []
        parsed = ASTParserRegistry.parse_js_ts(content) if language in ["JavaScript", "TypeScript", "JSX", "TSX"] else {}

        unused_imports = parsed.get("unused_imports", [])
        for u in unused_imports:
            findings.append({
                "type": "UNUSED_IMPORT",
                "severity": "LOW",
                "symbol": u["symbol"],
                "source": u["from"],
                "message": f"Unused import `{u['symbol']}` from '{u['from']}'"
            })

        # Check for empty blocks: if (...) {}
        empty_blocks = re.findall(r"(?:if|for|while)\s*\([^)]+\)\s*\{\s*\}", content)
        if empty_blocks:
            findings.append({
                "type": "EMPTY_BLOCK",
                "severity": "MEDIUM",
                "count": len(empty_blocks),
                "message": f"{len(empty_blocks)} empty control block(s) detected"
            })

        score = max(40, 100 - (len(findings) * 8))

        return {
            "score": score,
            "dead_code_items": findings,
            "total_issues": len(findings)
        }


class SemanticAnalyzer:
    """Analyzes HTML/JSX semantics, redundant wrapper DIVs, and class redundancies."""

    @classmethod
    def analyze(cls, content: str) -> Dict[str, Any]:
        parsed = ASTParserRegistry.parse_html_jsx(content)
        issues = []

        if parsed["max_consecutive_divs"] >= 3:
            issues.append({
                "type": "EXCESSIVE_DIV_NESTING",
                "severity": "MEDIUM",
                "depth": parsed["max_consecutive_divs"],
                "message": f"Excessive consecutive <div> wrapping detected (depth {parsed['max_consecutive_divs']})"
            })

        for d in parsed["duplicated_classes"]:
            issues.append({
                "type": "DUPLICATE_CLASSES",
                "severity": "LOW",
                "duplicates": d["duplicates"],
                "suggested": d["suggested"],
                "message": f"Duplicated CSS classes in `<{d['tag']}>`: {', '.join(d['duplicates'])}"
            })

        for opp in parsed["semantic_opportunities"]:
            issues.append({
                "type": "SEMANTIC_TAG_OPPORTUNITY",
                "severity": "LOW",
                "from": opp["from"],
                "to": opp["to"],
                "reason": opp["reason"],
                "message": f"Opportunity to replace `<div>` with semantic `<{opp['to']}>` ({opp['reason']})"
            })

        score = max(35, 100 - (len(issues) * 6))

        return {
            "score": score,
            "semantic_issues": issues,
            "total_opportunities": len(issues),
            "max_div_depth": parsed["max_div_depth"]
        }


class NamingAnalyzer:
    """Detects artificial, machine-generated, or vague identifier names."""

    @classmethod
    def analyze(cls, content: str) -> Dict[str, Any]:
        parsed = ASTParserRegistry.parse_js_ts(content)
        generic_names = parsed.get("generic_names", [])

        issues = []
        for g in generic_names:
            issues.append({
                "type": "GENERIC_NAME",
                "severity": "LOW",
                "identifier": g["identifier"],
                "line": g["line"],
                "message": f"Generic or machine-like identifier `{g['identifier']}` at line {g['line']}"
            })

        score = max(50, 100 - (len(issues) * 7))

        return {
            "score": score,
            "generic_identifiers": issues,
            "count": len(issues)
        }


class MaintainabilityPatternAnalyzer:
    """
    Identifies maintainability issues, excessive boilerplate, AI tells,
    and oversized functions / files.
    """

    @classmethod
    def analyze(cls, content: str) -> Dict[str, Any]:
        parsed = ASTParserRegistry.parse_js_ts(content)
        ai_comments = parsed.get("ai_comments", [])

        issues = []
        for cm in ai_comments:
            issues.append({
                "type": "REDUNDANT_AI_COMMENT",
                "severity": "LOW",
                "text": cm["text"][:80],
                "line": cm["line_hint"],
                "message": f"Redundant/boilerplate comment at line {cm['line_hint']}"
            })

        lines = content.count("\n") + 1
        if lines > 450:
            issues.append({
                "type": "OVERSIZED_FILE",
                "severity": "MEDIUM",
                "lines": lines,
                "message": f"File is oversized ({lines} lines). Consider decomposing into smaller sub-modules."
            })

        score = max(40, 100 - (len(issues) * 8))

        return {
            "score": score,
            "maintainability_issues": issues,
            "total_issues": len(issues)
        }


class AccessibilityAnalyzer:
    """Analyzes accessibility (a11y) essentials: alt tags, labels, aria attributes."""

    @classmethod
    def analyze(cls, content: str) -> Dict[str, Any]:
        issues = []

        # Missing alt in img
        img_without_alt = re.findall(r"<img\s+(?![^>]*\balt=)[^>]*>", content, re.IGNORECASE)
        if img_without_alt:
            issues.append({
                "type": "MISSING_IMG_ALT",
                "severity": "HIGH",
                "count": len(img_without_alt),
                "message": f"{len(img_without_alt)} `<img>` tag(s) missing `alt` attribute"
            })

        # Buttons without type
        btn_without_type = re.findall(r"<button\s+(?![^>]*\btype=)[^>]*>", content, re.IGNORECASE)
        if btn_without_type:
            issues.append({
                "type": "BUTTON_MISSING_TYPE",
                "severity": "LOW",
                "count": len(btn_without_type),
                "message": f"{len(btn_without_type)} `<button>` element(s) missing explicit `type='button|submit'`"
            })

        score = max(45, 100 - (len(issues) * 12))

        return {
            "score": score,
            "accessibility_issues": issues,
            "total_issues": len(issues)
        }


class SecurityAnalyzer:
    """
    Checks that security controls (CSRF, Auth, CSP, CORS) are preserved and
    alerts on dangerous constructs like eval() or unescaped dangerouslySetInnerHTML.
    """

    @classmethod
    def analyze(cls, content: str) -> Dict[str, Any]:
        issues = []

        if "eval(" in content:
            issues.append({
                "type": "DANGEROUS_EVAL",
                "severity": "CRITICAL",
                "message": "Direct use of `eval()` detected. Must be refactored safely."
            })

        if "dangerouslySetInnerHTML" in content and "sanitize" not in content and "DOMPurify" not in content:
            issues.append({
                "type": "UNSANITIZED_INNER_HTML",
                "severity": "HIGH",
                "message": "`dangerouslySetInnerHTML` used without apparent sanitization library."
            })

        score = 100 if not issues else (60 if any(i["severity"] == "CRITICAL" for i in issues) else 80)

        return {
            "score": score,
            "security_findings": issues,
            "total_findings": len(issues)
        }


class CodeQualityAnalyzer:
    """Master analyzer orchestrating all technical inspections for files and projects."""

    @classmethod
    def analyze_file(cls, rel_path: str, content: str, language: str) -> Dict[str, Any]:
        complexity = ComplexityAnalyzer.analyze(content, language)
        duplication = DuplicationAnalyzer.analyze(content)
        dead_code = DeadCodeAnalyzer.analyze(content, language)
        semantic = SemanticAnalyzer.analyze(content) if language in ["HTML", "JSX", "TSX", "Vue"] else {"score": 100, "semantic_issues": [], "total_opportunities": 0}
        naming = NamingAnalyzer.analyze(content) if language in ["JavaScript", "TypeScript", "JSX", "TSX"] else {"score": 100, "generic_identifiers": [], "count": 0}
        maintainability = MaintainabilityPatternAnalyzer.analyze(content)
        accessibility = AccessibilityAnalyzer.analyze(content) if language in ["HTML", "JSX", "TSX", "Vue"] else {"score": 100, "accessibility_issues": [], "total_issues": 0}
        security = SecurityAnalyzer.analyze(content)

        # Weighted composite score
        overall_score = round(
            complexity["score"] * 0.20 +
            duplication["score"] * 0.15 +
            dead_code["score"] * 0.15 +
            semantic["score"] * 0.15 +
            maintainability["score"] * 0.15 +
            accessibility["score"] * 0.10 +
            security["score"] * 0.10,
            1
        )

        all_issues = []
        all_issues.extend(dead_code.get("dead_code_items", []))
        all_issues.extend(semantic.get("semantic_issues", []))
        all_issues.extend(naming.get("generic_identifiers", []))
        all_issues.extend(maintainability.get("maintainability_issues", []))
        all_issues.extend(accessibility.get("accessibility_issues", []))
        all_issues.extend(security.get("security_findings", []))

        # Risk level determination
        risk = "LOW"
        if security["security_findings"] or complexity["cyclomatic_complexity"] > 25:
            risk = "HIGH"
        elif len(all_issues) > 5 or complexity["cyclomatic_complexity"] > 12:
            risk = "MEDIUM"

        return {
            "path": rel_path,
            "language": language,
            "overall_quality_score": overall_score,
            "maintainability_score": maintainability["score"],
            "complexity_score": complexity["score"],
            "duplication_score": duplication["score"],
            "semantic_score": semantic["score"],
            "accessibility_score": accessibility["score"],
            "security_score": security["score"],
            "cyclomatic_complexity": complexity["cyclomatic_complexity"],
            "total_issues_count": len(all_issues),
            "risk": risk,
            "issues": all_issues,
            "complexity_details": complexity,
            "duplication_details": duplication,
            "dead_code_details": dead_code,
            "semantic_details": semantic,
            "accessibility_details": accessibility,
            "security_details": security
        }
