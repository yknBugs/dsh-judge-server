"""`write` / `edit` 的本地检查，以及把写入内容交给分析器的那一步。

**这个文件不写文案。** 它只产出三样东西：规则名、等级、以及句子需要的数据。中文句子全部在
`writers.py` 里，按规则名对应。这样做的好处是改文案只动一个文件，而且句子能拿到这里量出来的
精确数字（写了多少字节、片段出现几次、文件多少行）。

本地检查管的是"目标本身"，与内容无关：路径是否可达、是否已存在、是不是目录、片段是否唯一、
文件是不是文本。内容检查只在文件属于分析器能读的语言时才做——一段 markdown 里写 `rm -rf /`
不会运行，把它当危险内容报出来就是噪音。
"""

from __future__ import annotations

import errno
import os
import stat as stat_module
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from analyzer_link import analyze_content, analyze_sql
from language import content_language

#: 片段出现次数报到这里为止，再多也没有额外信息。
MAX_OCCURRENCES = 20


@dataclass
class FileReport:
    findings: list[dict[str, Any]] = field(default_factory=list)

    def add(self, rule: str, level: str, data: dict | None = None, evidence: list | None = None) -> None:
        self.findings.append(
            {
                "rule": rule,
                "level": level,
                # 不需要 title/detail：渲染时由 writers.py 生成。
                "data": data or {},
                "evidence": evidence or [],
            }
        )


def _read_text(path: Path) -> tuple[str | None, str | None]:
    """文件文本，或读不出来的原因。"""
    try:
        raw = path.read_bytes()
    except OSError as error:
        return None, f"{error.__class__.__name__}"
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "not-utf8"


#: `_probe_path` 的几种结果。
DIRECTORY = "directory"
FILE = "file"
OTHER = "other"
#: 路径**确定不存在**（而不是"查不到"）。
ABSENT = "absent"
#: 查不到（权限、ACL、IO 错误…），和"不存在"必须分开。
UNKNOWN = ""

#: 这几类 `OSError` 表示"这个路径上没有东西"，可以当成确定的不存在。
#:
#: 和 `pathlib` 的 `_ignore_error` 保持同一套判据：`ENOENT`（没有）、`ENOTDIR`（路径中间是
#: 文件）、`ELOOP`（符号链接成环）、`EBADF`（非法的文件描述符）。**权限错误（EACCES）不在
#: 其中**——那是"我看不到"，不是"没有"。
_ABSENT_ERRNOS = frozenset(
    {errno.ENOENT, errno.ENOTDIR, errno.ELOOP, errno.EBADF}
)


def _probe_path(target: Path) -> tuple[str, str, int | None]:
    """查一次目标：`(类型, 出错原因, 字节数)`。

    **只调一次 `stat()`**，不再用 `is_dir()` / `is_file()` / `exists()` 那一串。原因：Python
    3.13 的 `is_file()` / `is_dir()` / `exists()` 只把 `ENOENT`/`ENOTDIR`/`ELOOP` 这类错误吞成
    False，**权限错误（EACCES）会重新抛出**，于是 ACL / 沙箱拒绝时判定器直接崩掉，而不是说
    "我查不到这个文件"。这里统一接住，交给调用方报成 `*-target-unreadable`。

    返回值：

    * `DIRECTORY` / `FILE` / `OTHER` —— 查到了，`size` 只有普通文件才有值；
    * `ABSENT` —— **确定**这个路径上没有东西；
    * `UNKNOWN` —— 查不到（`problem` 给异常类名）。这一种**不能**说成"不存在"。
    """
    try:
        info = target.stat()
    except OSError as error:
        if isinstance(error, FileNotFoundError) or error.errno in _ABSENT_ERRNOS:
            return ABSENT, "", None
        return UNKNOWN, f"{error.__class__.__name__}", None
    if stat_module.S_ISDIR(info.st_mode):
        return DIRECTORY, "", None
    if stat_module.S_ISREG(info.st_mode):
        return FILE, "", info.st_size
    return OTHER, "", None


def _escape_payload(text: str) -> str:
    """拼成单引号的 shell 词；POSIX 单引号里不能含单引号，所以闭合再重开。"""
    return "'" + text.replace("'", "'\\''") + "'"


def _join(prefix: str, name: str) -> str:
    """按 prefix 自己的分隔符风格拼路径。

    **不要用 `pathlib.Path` 拼用户给的路径。** `Path` 是按**运行平台**选的实现：Windows 上是
    `WindowsPath`，它会把 `/` 规范化成 `\\`。于是 Linux 用户传 `/srv/app/a.py`、判定器跑在
    Windows 上时，卡片上会印出 `\\srv\\app\\a.py` —— 一个他从没写过的路径。相对路径同理
    （`relative/x.py` 变成 `relative\\x.py`）。

    要"查这个文件"就用 `Path`；要"把路径显示出来或往下传"就保留原样。这两件事必须分开。
    """
    if not prefix:
        return name
    separator = "/" if "/" in prefix and "\\" not in prefix else os.sep
    return prefix.rstrip("/\\") + separator + name


def _parent_path(path_text: str) -> str:
    """路径的父目录，**纯字符串**运算，分隔符原样保留。

    不要用 `Path(path_text).parent`：`Path` 按运行平台选实现，Windows 上会把 POSIX 路径改写
    成盘符相对路径（`/srv/app/tools/x.py` -> `\\srv\\app\\tools`）。拿改写过的值当分析器的
    解析基准，内容里的相对路径就会落到另一个文件树上（实测 `open('y')` 变成
    `\\srv\\app\\tools/y`，还被判成"工作区外"）。
    """
    text = path_text.rstrip("/\\")
    cut = max(text.rfind("/"), text.rfind("\\"))
    if cut <= 0:
        return ""
    return text[:cut]


def _analyse(path_text: str, target: Path, content: str, report: FileReport, workspace: str) -> None:
    """写入内容是分析器能读的语言时，把它送进分析器。

    **内容直接交给分析器的内容入口，不包装成命令。** 以前这里拼出一条 `printf %s '…' > '…'`
    再分析，后果有二：那条包装只有 bash 懂，`.ps1`/`.bat`/`.py` 的内容被当 bash 解析，卡片上
    出现 `包含未知命令 printf`、`包含未知命令 def`（那是包装命令和 Python 语法）；而且分析器会
    把**命令**的未解析值贴到**内容**上。

    两件事要分开，分析器 1.10.0 起支持：

    * `cwd` —— **解析基准**，相对路径落在哪儿。取被写文件的目录（`_parent_path` 的**字符串**
      结果），内容里的 `open("data.txt")` 指的就是文件旁边那个 data.txt；
    * `workspace` —— **工作区边界**，"有没有脱离用户指定的目录"。取会话的 `working_space`。
      **它和被写文件放在哪个子目录一点关系都没有。**

    `path_text` 是**原样**的路径（分隔符不被改写），`target` 只是同一个路径的 `Path` 形式，
    给磁盘探测用。
    """
    language = content_language(path_text)
    if language is None:
        return
    # 解析基准用**字符串**父目录：`Path(...)` 会把 POSIX 路径改写成盘符相对路径。
    base = _parent_path(path_text) or workspace or str(target.parent)
    if language == "sql":
        outcome = analyze_sql(content)
    else:
        outcome = analyze_content(content, language, path_text, cwd=base,
                                  workspace_root=workspace or base)
    if not outcome.reached:
        report.add("analyzer-error", "MEDIUM", {"reason": outcome.unavailable_reason})
        return
    for finding in outcome.findings:
        data = dict(finding.get("data") or {})
        data.setdefault("written_file", path_text)
        report.findings.append({**finding, "data": data})


def _resolve(path: str, cwd: str) -> str:
    """相对路径按 cwd 拼成绝对路径，**分隔符保持原样**。

    用 `_join` 而不是 `Path`/`os.path.join`：后两者按运行平台改写分隔符，会把 Linux 用户写的
    `/srv/app/a.py` 变成 `\\srv\\app\\a.py`。
    """
    if not cwd or (len(path) >= 2 and path[1] == ":") or path.startswith("/"):
        return path
    return _join(cwd, path)


def is_absolute_path(text: str) -> bool:
    """`/…` 或 `X:…` 都算绝对路径。

    **不要用 `os.path.isabs`**：它在 Windows 上对 `/etc/motd` 返回 False（没有盘符），于是
    POSIX 绝对路径会被当成相对路径拼到 cwd 后面，工作区包含性判断随之出错。
    """
    return text.startswith("/") or (len(text) >= 2 and text[1] == ":")


def within_workspace(path_text: str, cwd: str) -> bool:
    """目标是否落在工作目录内（**词法**判断）。

    不碰 `os.path.commonpath`/`abspath`：那两个按运行平台解释路径，Windows 上会把 POSIX 路径
    当成单段相对路径（`/etc/motd` 看起来像个普通文件名），而且 `os.path.join` 会拼出
    `/srv/app\\sub/x.txt` 这种混合分隔符。分隔符风格对不上时按"不在内"处理——安全的方向。

    两个路径都要先解析成绝对路径再传进来（相对路径的落点取决于 cwd）。
    """
    if not path_text or not cwd:
        return False
    normalized = path_text.replace("\\", "/")
    root = cwd.replace("\\", "/").rstrip("/")
    if not root:
        return False
    return normalized == root or normalized.startswith(root + "/")


#: 旧名字，保留给既有调用点。
_inside = within_workspace


def normalise_path(path_text: str) -> str:
    """**词法**折叠 `.` 与 `..`，分隔符风格原样保留，不碰磁盘。

    `within_workspace` 是纯前缀比较，它看不见 `..`：`/work/sub/../..` 以 `/work/` 开头，
    所以会被判成"在区内"，而它实际指向 `/`。`working_directory` 的 `cd` 必须能拦住这种写法，
    否则"跳出工作区"的检查形同虚设。

    折叠是**纯文本**的：不解析符号链接、不查磁盘（那需要 IO，而且不同平台语义不同）。
    """
    if not path_text:
        return path_text
    raw = path_text.replace("\\", "/")
    drive = ""
    if len(raw) >= 2 and raw[1] == ":":
        drive, raw = raw[:2], raw[2:]
    absolute = raw.startswith("/")
    parts: list[str] = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            elif not absolute:
                # 相对路径往上走过头，`..` 要留着——它代表 cwd 的父目录。
                parts.append("..")
            # 绝对路径已经到根，再往上还是根。
            continue
        parts.append(part)
    joined = "/".join(parts)
    if absolute:
        joined = "/" + joined
    result = drive + joined
    if "\\" in path_text and "/" not in path_text:
        result = result.replace("/", "\\")
    if not result:
        return "/" if absolute else "."
    return result


def resolve_path(path: str, cwd: str) -> str:
    """把 `path` 解析成绝对路径并折叠 `..`；分隔符风格**按输入决定，不看运行平台**。

    故意不用 `_join`：那个在"前缀里没有任何分隔符线索"时会退到 `os.sep`，于是同一份输入在
    Windows 和 Linux 上拼出不同的字符串（`D:\\work/sub` 之类）。这里的规则只有一条——**cwd 用
    哪种分隔符，拼出来就用哪种**；cwd 自己没线索时用 `/`（POSIX 是唯一能被所有平台读懂的写法）。
    """
    if not path:
        return ""
    if is_absolute_path(path) or not cwd:
        return normalise_path(path)
    separator = "\\" if "\\" in cwd and "/" not in cwd else "/"
    return normalise_path(cwd.rstrip("/\\") + separator + path)


def check_write(path: str, args: dict[str, Any], cwd: str, workspace: str = "") -> FileReport:
    """`write` 的检查。

    `cwd` 是**解析基准**（相对路径落在哪）；`workspace` 是**工作区边界**（用户指定的目录）。
    插件把两者分开送了，`working_directory` 可以把 `cwd` 挪到别处而 `workspace` 不变。
    `workspace` 缺省时退回 `cwd`（老插件只发一个值）。
    """
    boundary = workspace or cwd
    report = FileReport()
    # `path_text` 是**给人看、往下传**的路径（分隔符原样）；`target` 只用来查磁盘。
    path_text = _resolve(path, cwd)
    target = Path(path_text)
    content = args.get("content")

    if boundary and not _inside(path_text, boundary):
        report.add("write-outside-workspace", "MEDIUM",
                   {"target": path_text, "cwd": boundary, "check": "write"})

    kind, problem, existing = _probe_path(target)
    if problem:
        # 查不到状态：既不敢说"会覆盖"，也不敢说"是新建"。**明说不知道**，别静默放行。
        report.add("write-target-unreadable", "MEDIUM",
                   {"target": path_text, "reason": problem, "check": "write"})
    elif kind == DIRECTORY:
        report.add("write-target-is-directory", "MEDIUM", {"target": path_text, "check": "write"})
    elif kind == FILE:
        report.add("overwrite-existing-file", "LOW",
                   {"target": path_text, "existing_bytes": existing, "check": "write"})

    if isinstance(content, str):
        written = len(content.encode("utf-8"))
        report.add("write-size", "LOW",
                   {"target": path_text, "written_bytes": written,
                    "existing_bytes": existing if kind == FILE else None, "check": "write"})
        _analyse(path_text, target, content, report, boundary)
    return report


def check_edit(path: str, args: dict[str, Any], cwd: str, workspace: str = "") -> FileReport:
    """`edit` 的检查。`cwd` 解析基准、`workspace` 工作区边界，语义同 `check_write`。"""
    boundary = workspace or cwd
    report = FileReport()
    path_text = _resolve(path, cwd)
    target = Path(path_text)

    old = args.get("old_string") or args.get("oldString") or ""
    new = args.get("new_string") or args.get("newString") or ""
    if not isinstance(old, str):
        old = ""
    if not isinstance(new, str):
        new = ""

    if boundary and not _inside(path_text, boundary):
        report.add("write-outside-workspace", "MEDIUM",
                   {"target": path_text, "cwd": boundary, "check": "edit"})

    kind, problem, _existing = _probe_path(target)
    if problem:
        # 查不到状态，就**不能说"不存在"**：`edit-target-missing` 只在真正确认没有时才发。
        report.add("edit-target-unreadable", "MEDIUM",
                   {"target": path_text, "reason": problem, "check": "edit"})
        return report
    if kind == DIRECTORY:
        report.add("write-target-is-directory", "MEDIUM", {"target": path_text, "check": "edit"})
        return report
    if kind != FILE:
        # `ABSENT` 或 `OTHER`（设备、管道…）：都不是能编辑的普通文件。
        report.add("edit-target-missing", "MEDIUM", {"target": path_text, "check": "edit"})
        return report

    text, problem = _read_text(target)
    if problem == "not-utf8":
        report.add("edit-target-not-utf8", "MEDIUM", {"target": path_text, "check": "edit"})
        return report
    if text is None:
        report.add("edit-target-unreadable", "MEDIUM",
                   {"target": path_text, "reason": problem, "check": "edit"})
        return report

    original_bytes = len(text.encode("utf-8"))
    if old == "":
        report.add("edit-empty-fragment", "MEDIUM", {"target": path_text, "check": "edit"})
        return report

    occurrences = text.count(old)
    counts = {"target": path_text, "occurrences": occurrences, "characters": len(text),
              "check": "edit"}

    if old == new:
        report.add("edit-no-change", "LOW", counts)
    if occurrences == 0:
        report.add("edit-fragment-missing", "MEDIUM", counts)
        return report
    if occurrences > 1:
        report.add("edit-fragment-ambiguous", "MEDIUM", counts)

    updated = text.replace(old, new, 1)
    after_bytes = len(updated.encode("utf-8"))
    report.add("edit-size-change", "LOW",
               {**counts, "before_bytes": original_bytes, "after_bytes": after_bytes,
                "delta_bytes": after_bytes - original_bytes, "lines": len(text.splitlines())})

    _analyse(path_text, target, updated, report, boundary)
    return report
