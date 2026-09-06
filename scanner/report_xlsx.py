import pandas as pd
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

def generate_xlsx(output_path: str, target_url: str, findings: List[Dict[str, Any]], crawl_stats: Dict[str, Any], operator: str, project_name: str) -> None:
    """
    Generate an XLSX report summarizing pentest findings.
    Designed for Office 365 Copilot / AI ingestion.
    """
    with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
        
        # 1. Summary Sheet
        summary_data = {
            "Item": ["Project Name", "Target URL", "Operator / Author", "Date", "Total Findings", "Critical", "High", "Medium", "Low", "Total URLs Discovered"],
            "Value": [
                project_name,
                target_url,
                operator,
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                len(findings),
                sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL"),
                sum(1 for f in findings if f.get("severity", "").upper() == "HIGH"),
                sum(1 for f in findings if f.get("severity", "").upper() == "MEDIUM"),
                sum(1 for f in findings if f.get("severity", "").upper() == "LOW"),
                crawl_stats.get("total", 0)
            ]
        }
        df_summary = pd.DataFrame(summary_data)
        df_summary.to_excel(writer, sheet_name="Summary", index=False)
        
        # 2. Findings Sheet
        if findings:
            df_findings = pd.DataFrame(findings)
            # Reorder columns to have the most important first if they exist
            cols_order = ["title", "severity", "cvss_score", "owasp", "cwe", "affected_url", "description", "recommendation", "evidence"]
            existing_cols = [c for c in cols_order if c in df_findings.columns]
            other_cols = [c for c in df_findings.columns if c not in existing_cols]
            df_findings = df_findings[existing_cols + other_cols]
            df_findings.to_excel(writer, sheet_name="Findings", index=False)
        else:
            df_findings = pd.DataFrame([{"Message": "No vulnerabilities found."}])
            df_findings.to_excel(writer, sheet_name="Findings", index=False)
            
        # 3. Assets Sheet
        if crawl_stats and "urls" in crawl_stats:
            assets = crawl_stats.get("urls", [])
            df_assets = pd.DataFrame(assets)
            df_assets.to_excel(writer, sheet_name="Assets", index=False)
        else:
            df_assets = pd.DataFrame([{"Message": "No assets recorded."}])
            df_assets.to_excel(writer, sheet_name="Assets", index=False)
            
        # Optional formatting: adjust column widths automatically
        for sheet_name in writer.sheets:
            worksheet = writer.sheets[sheet_name]
            for col in worksheet.columns:
                max_length = 0
                column = col[0].column_letter
                for cell in col:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(cell.value)
                    except:
                        pass
                adjusted_width = (max_length + 2)
                # Cap the maximum width to prevent excessively wide columns
                worksheet.column_dimensions[column].width = min(adjusted_width, 100)
