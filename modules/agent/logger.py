"""
modules/agent/logger.py
AgentMarkdownLog — live Markdown report written round-by-round during agent runs.

Functions that live in _core.py (_command_preview_for_tool, build_attack_chain_plan)
are imported lazily inside methods to avoid circular imports at module load time.
"""
import re
from pathlib import Path
from datetime import datetime

from config.settings import SESSION, redact_text


class AgentMarkdownLog:
    """Live Markdown report that grows as the agent progresses."""

    def __init__(self, path: Path, target: str, domain: str, model: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lines: list[str] = []
        self._write_header(target, domain, model)
        if not self.path.exists():
            print(f"  [!] WARNING: Could not create report at {self.path}")

    def _write_header(self, target: str, domain: str, model: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._lines += [
            "# AdStrike — Scan Report",
            "**Creator:** tmrswrr  |  **Framework:** AdStrike v5.0 «AdStrike»",
            f"**Date:** {ts}  |  **Target:** `{target}`  |  **Domain:** `{domain}`  |  **Model:** `{model}`",
            "",
            "> **AUTHORIZED PENETRATION TESTING ONLY**",
            "",
            "---",
            "",
            "## Scan Progress",
            "",
        ]
        self._flush()

    @staticmethod
    def _clean(text: str, max_len: int = 2000) -> str:
        """Strip ANSI codes, control chars, and truncate for Markdown safety."""
        text = re.sub(r'\x1b\[[0-9;]*[mABCDEFGHJKSTfhilmnprsu]', '', text)
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        text = redact_text(text)
        if len(text) > max_len:
            text = text[:max_len] + "\n...[truncated]"
        return text.strip()

    def add_round(self, round_num: int, tool_name: str, args: dict, result: str,
                  commands: list[str] | None = None):
        """Append a tool-call entry to the report."""
        # Lazy import avoids circular dependency with _core at module load time
        from modules.agent._core import _command_preview_for_tool

        ts           = datetime.now().strftime("%H:%M:%S")
        result_clean = self._clean(result)
        shown_commands = [
            self._clean(cmd, max_len=400)
            for cmd in (commands or _command_preview_for_tool(tool_name, args))
            if str(cmd or "").strip()
        ]
        if not shown_commands:
            shown_commands = _command_preview_for_tool(tool_name, args)

        if len(shown_commands) == 1:
            command_lines = [f"**Command:** `{shown_commands[0]}`"]
        else:
            command_lines = ["**Commands:**", "```"]
            command_lines.extend(shown_commands[:20])
            if len(shown_commands) > 20:
                command_lines.append(f"...[{len(shown_commands) - 20} more commands]")
            command_lines.append("```")

        self._lines += [
            f"### Round {round_num} — `{tool_name}`  <sup>{ts}</sup>",
            "",
            *command_lines,
            "",
            "**Result:**",
            "```",
            result_clean,
            "```",
            "",
        ]
        self._flush()

    def add_finding(self, title: str, severity: str, description: str):
        sev_emoji = {
            "Critical": "🔴", "High": "🟠", "Medium": "🟡",
            "Low": "🟢", "Info": "🔵",
        }.get(severity, "⚪")
        self._lines += [
            f"### {sev_emoji} FINDING [{severity}]: {title}",
            "",
            f"> {self._clean(description, max_len=1200)}",
            "",
        ]
        self._flush()

    def add_summary(self, round_num: int, status: str,
                    findings: list, owned_u: list, owned_m: list, loot: dict):
        # Lazy import avoids circular dependency with _core
        from modules.agent._core import build_attack_chain_plan

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sev_counts = {s: sum(1 for f in findings if f.get("severity") == s)
                      for s in ["Critical", "High", "Medium", "Low", "Info"]}

        self._lines += [
            "---",
            "",
            "## Mission Summary",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| **Status** | `{status.upper()}` |",
            f"| **Completed at** | {ts} |",
            f"| **Rounds** | {round_num} |",
            f"| **Total Findings** | {len(findings)} |",
            f"| **Critical** | {sev_counts['Critical']} |",
            f"| **High** | {sev_counts['High']} |",
            f"| **Medium** | {sev_counts['Medium']} |",
            f"| **Owned Users** | {', '.join(owned_u) or 'None'} |",
            f"| **Owned Machines** | {', '.join(owned_m) or 'None'} |",
            "",
        ]

        if loot:
            self._lines += ["## Captured Hashes", ""]
            for acct in loot.keys():
                self._lines.append(f"- `{acct}` → `***`")
            self._lines.append("")

        if findings:
            self._lines += ["## Findings", ""]
            for f in findings:
                sev   = f.get("severity", "Info")
                emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡",
                         "Low": "🟢", "Info": "🔵"}.get(sev, "⚪")
                self._lines += [
                    f"### {emoji} [{sev}] {f.get('name', '?')}",
                    "",
                    f"**Description:** {self._clean(f.get('description', ''), max_len=1200)}",
                    "",
                    f"**Recommendation:** {self._clean(f.get('recommendation', ''), max_len=1200)}",
                    "",
                ]

        plans = build_attack_chain_plan()
        if plans:
            self._lines += ["## Attack Chain Plan", ""]
            for idx, plan in enumerate(plans, 1):
                self._lines += [
                    f"### {idx}. {self._clean(plan.get('title', 'Attack chain'), max_len=160)}",
                    "",
                    f"**Confidence:** `{plan.get('confidence', 'unknown')}`",
                    "",
                    f"**Why:** {self._clean(plan.get('why', ''), max_len=500)}",
                    "",
                    "```bash",
                ]
                self._lines.extend(
                    self._clean(cmd, max_len=500)
                    for cmd in plan.get("commands", [])[:28]
                )
                self._lines += ["```", ""]

        self._lines += [
            "---",
            "*Generated by AdStrike v5.0 «AdStrike» · creator: tmrswrr*",
        ]
        self._flush()

    def _flush(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            content = "\n".join(self._lines)
            content = re.sub(r'\x1b\[[0-9;]*[mABCDEFGHJKSTfhilmnprsu]', '', content)
            content = redact_text(content)
            self.path.write_text(content, encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"\n  [!] Report write error: {e} → {self.path}")
