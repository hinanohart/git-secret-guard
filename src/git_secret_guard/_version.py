"""Single source of truth for the package version.

Kept in its own module so ``pyproject.toml`` and CI scripts can read the
string without importing the full package.
"""

from __future__ import annotations

__version__ = "0.1.0"
