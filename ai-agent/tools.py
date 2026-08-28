from __future__ import annotations

import subprocess
from pathlib import Path

from langchain_core.tools import tool

MODULE_DIR = Path(__file__).resolve().parent


@tool
def shell(command: str) -> str:
    """
    Run shell commands only. This tool should only be invoked to execute shell commands and not for any other purpose such as retrieving weather details or unrelated queries.
    """
    command_text = command.strip()
    if not command_text:
        raise ValueError("Command must not be empty.")

    completed = subprocess.run(
        ["bash", "-lc", command_text],
        cwd=str(MODULE_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    return (
        f"exit_code: {completed.returncode}\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )


TOOLS = [shell]
