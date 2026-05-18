"""
modules/agent — AdStrike Agent package.

Submodule layout:
  constants.py  — all configuration and environment-driven settings
  backends.py   — AI API adapters (Ollama local, Anthropic Claude)
  logger.py     — AgentMarkdownLog: live Markdown report written per round
  _core.py      — core implementation (utils, exec helpers, intel,
                   system prompts, tool handlers, orchestration loops)

External entry point:
  from modules.agent import run   # or via modules.red_team_agent (shim)
"""
from modules.agent._core import run  # noqa: F401
