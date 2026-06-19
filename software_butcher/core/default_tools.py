"""Register a few example/default tools into the registry.

These are lightweight example specs that map tool names to adapters and
provide argument lists. Real integrations can register richer commands.
"""

from .registry import register_default_tool
import sys


# Use the Python executable to print text so tests are hermetic on Windows
register_default_tool(
    name="hex_echo",
    adapter="hexstrike",
    command=[sys.executable, "-c", "print('hexstrike:scan')"],
    description="Example hexstrike tool (python print placeholder)",
)

register_default_tool(
    name="boaz_echo",
    adapter="boaz",
    command=[sys.executable, "-c", "print('boaz:run')"],
    description="Example BOAZ tool (python print placeholder)",
)
