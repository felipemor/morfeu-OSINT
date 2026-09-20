"""
AST Parsers & Tree Extractors for HTML, CSS, JavaScript, TypeScript, JSX & TSX
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple


class ASTParserRegistry:
    """Parses source code into structured tokens, AST nodes, and semantic metadata."""

    # ── HTML / JSX PARSER ──────────────────────────────────────────────────────
    @classmethod
    def parse_html_jsx(cls, code: str) -> Dict[str, Any]:
        """
        Parses HTML and JSX markup, extracting tag hierarchies, attributes,
        duplicated class lists, deeply nested containers, and semantic candidates.
        """
        tag_pattern = re.compile(r"<(/?)(\w+)([^>]*?)(\/?)>", re.MULTILINE | re.DOTALL)
        class_pattern = re.compile(r'(?:class|className)=["\']([^"\']+)["\']')
        
        tags_found = []
        nested_div_depth = 0
        max_div_depth = 0
        consecutive_div_wrappers = 0
        max_consecutive_divs = 0
        current_consecutive_divs = 0

        duplicated_classes = []
        empty_elements = []
        semantic_opportunities = []

        pos = 0
        for match in tag_pattern.finditer(code):
            is_closing = bool(match.group(1))
            tag_name = match.group(2).lower()
            attrs_str = match.group(3)
            is_self_closing = bool(match.group(4))

            # Class inspection
            for cm in class_pattern.finditer(attrs_str):
                raw_classes = cm.group(1).split()
                seen = set()
                dupes = [c for c in raw_classes if c in seen or seen.add(c)]
                if dupes:
                    duplicated_classes.append({
                        "tag": tag_name,
                        "duplicates": list(set(dupes)),
                        "original_string": cm.group(0),
                        "suggested": " ".join(dict.fromkeys(raw_classes))
                    })

            # Check for excessive DIV nesting
            if tag_name == "div":
                if not is_closing:
                    nested_div_depth += 1
                    current_consecutive_divs += 1
                    max_div_depth = max(max_div_depth, nested_div_depth)
                    max_consecutive_divs = max(max_consecutive_divs, current_consecutive_divs)
                else:
                    nested_div_depth = max(0, nested_div_depth - 1)
                    current_consecutive_divs = 0
            else:
                current_consecutive_divs = 0

            # Semantic replacement opportunities
            if tag_name == "div" and not is_closing:
                attrs_low = attrs_str.lower()
                if "header" in attrs_low or "topbar" in attrs_low or "navbar" in attrs_low:
                    semantic_opportunities.append({"from": "div", "to": "header", "reason": "Header / Navbar container"})
                elif "nav" in attrs_low or "menu" in attrs_low or "sidebar" in attrs_low:
                    semantic_opportunities.append({"from": "div", "to": "nav", "reason": "Navigation container"})
                elif "footer" in attrs_low or "bottom" in attrs_low:
                    semantic_opportunities.append({"from": "div", "to": "footer", "reason": "Footer element"})
                elif "article" in attrs_low or "card" in attrs_low or "post" in attrs_low:
                    semantic_opportunities.append({"from": "div", "to": "article", "reason": "Self-contained content card"})
                elif "main" in attrs_low or "content" in attrs_low or "page-body" in attrs_low:
                    semantic_opportunities.append({"from": "div", "to": "main", "reason": "Primary content region"})

            tags_found.append({
                "tag": tag_name,
                "is_closing": is_closing,
                "is_self_closing": is_self_closing,
                "attrs": attrs_str.strip()
            })

        return {
            "total_tags": len(tags_found),
            "max_div_depth": max_div_depth,
            "max_consecutive_divs": max_consecutive_divs,
            "duplicated_classes": duplicated_classes,
            "semantic_opportunities": semantic_opportunities,
            "tags": tags_found[:100]
        }

    # ── CSS / SCSS PARSER ──────────────────────────────────────────────────────
    @classmethod
    def parse_css(cls, code: str) -> Dict[str, Any]:
        """
        Parses CSS/SCSS rules, extracting selectors, properties, duplicates,
        redundant media queries, and consolidation opportunities.
        """
        rule_pattern = re.compile(r"([^{]+)\{([^}]+)\}", re.MULTILINE)
        selectors_map: Dict[str, List[Dict[str, str]]] = {}
        duplicate_rules: List[Dict[str, Any]] = []
        total_rules = 0

        for match in rule_pattern.finditer(code):
            raw_selector = match.group(1).strip()
            body = match.group(2).strip()

            if raw_selector.startswith("@"):
                continue  # skip media queries or keyframe headers in top-level selector list

            total_rules += 1
            # parse properties
            props = {}
            for line in body.split(";"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    props[k.strip()] = v.strip()

            if raw_selector in selectors_map:
                duplicate_rules.append({
                    "selector": raw_selector,
                    "first_declaration": selectors_map[raw_selector],
                    "second_declaration": props
                })
                selectors_map[raw_selector].append(props)
            else:
                selectors_map[raw_selector] = [props]

        return {
            "total_rules": total_rules,
            "unique_selectors": len(selectors_map),
            "duplicate_selectors": duplicate_rules,
            "consolidation_candidates": len(duplicate_rules)
        }

    # ── JAVASCRIPT / TYPESCRIPT PARSER ─────────────────────────────────────────
    @classmethod
    def parse_js_ts(cls, code: str) -> Dict[str, Any]:
        """
        Parses JS/TS/TSX code, extracting imports, exports, functions, hooks,
        unused symbols, comments, and generic identifier names.
        """
        import_pattern = re.compile(r"import\s+(?:(?:\*\s+as\s+\w+)|(?:\{[^}]+\})|(?:[\w\s,]+))\s+from\s+['\"]([^'\"]+)['\"];?", re.MULTILINE)
        named_import_pattern = re.compile(r"import\s+\{([^}]+)\}\s+from\s+['\"]([^'\"]+)['\"]")
        default_import_pattern = re.compile(r"import\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]")
        
        function_pattern = re.compile(r"(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|class\s+(\w+))")
        hook_pattern = re.compile(r"use([A-Z]\w+)\s*\(")
        comment_pattern = re.compile(r"//.*|/\*[\s\S]*?\*/")

        all_imports = []
        imported_symbols = set()
        
        for m in named_import_pattern.finditer(code):
            symbols = [s.strip().split(" as ")[-1].strip() for s in m.group(1).split(",") if s.strip()]
            for s in symbols:
                imported_symbols.add((s, m.group(2)))

        for m in default_import_pattern.finditer(code):
            imported_symbols.add((m.group(1).strip(), m.group(2)))

        # Find unused imports (rough AST symbol reference check)
        unused_imports = []
        # Remove import statements from body before searching for usages
        code_without_imports = import_pattern.sub("", code)
        for sym, source in imported_symbols:
            # Check if symbol appears as a word in the code body
            if not re.search(rf"\b{re.escape(sym)}\b", code_without_imports):
                unused_imports.append({"symbol": sym, "from": source})

        # Functions found
        functions = []
        for m in function_pattern.finditer(code):
            name = m.group(1) or m.group(2) or m.group(3)
            if name:
                functions.append(name)

        # React hooks
        hooks_used = list(set(hook_pattern.findall(code)))

        # AI tell comments & redundant comments
        ai_comments = []
        for cm in comment_pattern.finditer(code):
            comment_text = cm.group(0).lower()
            if any(w in comment_text for w in [
                "ai generated", "generated by ai", "this component was generated",
                "this function handles", "not x but y", "here is the", "important:"
            ]):
                ai_comments.append({
                    "text": cm.group(0).strip(),
                    "line_hint": code[:cm.start()].count("\n") + 1
                })

        # Generic / artificial identifier names
        generic_names = []
        generic_pattern = re.compile(r"\b(div\d+|container\d+|dataFinal\d*|tempData\d*|handleClickNew\d*|componentFinal\d*|var\d+|obj\d+)\b")
        for gm in generic_pattern.finditer(code):
            generic_names.append({
                "identifier": gm.group(1),
                "line": code[:gm.start()].count("\n") + 1
            })

        return {
            "total_imports": len(imported_symbols),
            "unused_imports": unused_imports,
            "functions_declared": functions,
            "hooks_used": hooks_used,
            "ai_comments": ai_comments,
            "generic_names": generic_names,
            "lines_count": code.count("\n") + 1
        }
