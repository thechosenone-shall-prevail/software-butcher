"""Software Butcher private reasoning harness."""

__all__ = ["__version__"]

# Ensure default tool specs register on package import
try:
	from .core import default_tools  # type: ignore
except Exception:
	# Best-effort import; tests may import submodules directly.
	default_tools = None  # type: ignore

__version__ = "0.1.0"
