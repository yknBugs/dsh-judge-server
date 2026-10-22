"""Which language a file's CONTENTS are in, by extension, basename, or shebang.

Only languages the analyzer can read as executable or query text are reported. Everything else is
data: writing markdown cannot make anything run, so there is nothing to interpret and no finding
is warranted. Guessing here would be the same mistake as guessing a shell from a path's shape.
"""

from __future__ import annotations

import os
import re

SHELL_EXTENSIONS = {".sh": "bash", ".bash": "bash", ".zsh": "bash", ".ksh": "bash", ".dash": "bash"}
POWERSHELL_EXTENSIONS = {".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell"}
CMD_EXTENSIONS = {".bat": "cmd", ".cmd": "cmd"}
SQL_EXTENSIONS = {".sql": "sql"}

#: Executable files that carry no extension.
SHELL_BASENAMES = {".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".kshrc"}
POWERSHELL_BASENAMES = {"profile.ps1", "microsoft.powershell_profile.ps1"}

#: Python is accepted because the analyzer parses it natively when it arrives through a command;
#: a written .py file is inspected for the same shapes.
PYTHON_EXTENSIONS = {".py": "python"}

#: JavaScript 是分析器 1.10.0 新增的第六门前端。后缀取**和分析器自己那张表一致**的三个
#: （`detectors.py` 的 `language()`：`.js`/`.mjs`/`.cjs`）。`.jsx`/`.ts` 不在里面——tree-sitter-javascript
#: 不认 TypeScript 语法，把它们当 JS 分析只会得到一堆语法错误，那不是"发现"。
JAVASCRIPT_EXTENSIONS = {".js": "javascript", ".mjs": "javascript", ".cjs": "javascript"}

_TABLES = (SHELL_EXTENSIONS, POWERSHELL_EXTENSIONS, CMD_EXTENSIONS, SQL_EXTENSIONS,
           PYTHON_EXTENSIONS, JAVASCRIPT_EXTENSIONS)

_SHEBANG = re.compile(r"^#!\s*(?:\S*/)?(?P<name>[A-Za-z0-9_.+-]+)")


def content_language(path: str, content: str | None = None) -> str | None:
    """The dialect of a file's contents, or None when nothing about it is executable."""
    base = os.path.basename(path).lower()
    if base in SHELL_BASENAMES:
        return "bash"
    if base in POWERSHELL_BASENAMES:
        return "powershell"
    extension = os.path.splitext(base)[1]
    for table in _TABLES:
        if extension in table:
            return table[extension]
    if content:
        match = _SHEBANG.match(content.lstrip("\ufeff"))
        if match:
            name = match.group("name").lower()
            if name in {"sh", "bash", "zsh", "ksh", "dash"}:
                return "bash"
            if name in {"pwsh", "powershell"}:
                return "powershell"
            if name in {"python", "python3", "py"}:
                return "python"
    return None


def is_sql(path: str) -> bool:
    return content_language(path) == "sql"
