"""Non-content checks for the read and search tools: reach, and credential-shaped targets.

Per the policy these are the only two things worth reporting here — where the call reaches, and
whether what it reaches is credential material that would enter the model's context. Search
results are not interpreted; a glob or grep has no contents to inspect before it runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from filechecks import is_absolute_path, within_workspace

#: Path shapes that name credential material. Kept narrow on purpose: a file merely CALLED
#: `secrets.md` is documentation, while `id_rsa`, `.env` and `credentials` are stores.
#:
#: The name is matched anywhere in the basename, not only at a separator: `secrets.env` and
#: `prod.env` are stores too, and requiring the `.env` to be the whole name was a miss.
CREDENTIAL_NAMES = re.compile(
    r"(?i)(?:"
    r"\.env(?:\.[a-z0-9_-]+)?\b|\.netrc|\.pgpass|\.npmrc|credentials(?:\.json)?\b|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)\b|\.git-credentials|\.kdbx\b|\.p12\b|\.pfx\b|\.ppk\b|"
    r"\.ssh[\\/]|\.aws[\\/]|\.gnupg[\\/]|\.dsh[\\/]"
    r")"
)

#: Directories that are scratch space rather than somewhere a decision is being made.
TEMP_MARKERS = ("\\temp\\", "/tmp/", "/var/tmp/", "/dev/shm/", "\\appdata\\local\\temp\\")


@dataclass
class ReadReport:
    findings: list[dict[str, Any]] = field(default_factory=list)

    def add(self, rule: str, level: str, data: dict | None = None) -> None:
        # 不写文案：中文句子在 writers.py，按规则名对应。
        self.findings.append({"rule": rule, "level": level, "data": data or {}, "evidence": []})


def check_read(tool: str, path: str, args: dict[str, Any], cwd: str, workspace: str = "") -> ReadReport:
    """读类工具的触及范围检查。

    `cwd` 是**解析基准**（相对路径落在哪）；`workspace` 是**工作区边界**（用户指定的目录）。
    插件把两者分开送了，`working_directory` 可以把 `cwd` 挪走而 `workspace` 不变。`workspace`
    缺省时退回 `cwd`（老插件只发一个值）。
    """
    boundary = workspace or cwd
    report = ReadReport()
    lowered = path.replace("\\", "/").lower()
    in_temp = any(marker in lowered for marker in TEMP_MARKERS)

    if boundary and not path.startswith("**") and not path.startswith("*"):
        # 包含性判断走 `filechecks` 那套**词法**实现，不用 `os.path`：`os.path.isabs("/etc/motd")`
        # 在 Windows 上是 False（没有盘符），于是 POSIX 绝对路径会被当成相对路径拼到 cwd 后面，
        # 判断结果就反了；`os.path.join` 还会拼出 `/srv/app\\sub/x.txt` 这种混合分隔符。
        base = cwd or boundary
        candidate = path if is_absolute_path(path) else f"{base.rstrip('/')}/{path}"
        inside = within_workspace(candidate, boundary)
        if not inside and not in_temp:
            report.add("read-outside-workspace", "LOW",
                       {"target": path, "cwd": boundary, "tool": tool})

    if CREDENTIAL_NAMES.search(path):
        report.add("credentials-read", "MEDIUM", {"target": path, "tool": tool})
    return report
