"""Thin wrapper over the command_inspector analyzer.

Everything that touches the analyzer library lives here, so the policy layer above can be tested
without one. Three things this wrapper owns:

* locating the analyzer package (installed, or pointed at by an environment variable), because
  the judge is meant to be usable against a checkout as well as an installed copy;
* turning its exceptions into `AnalysisOutcome` values instead of letting them escape, so a
  crash inside the analyzer becomes a visible "could not analyse" ask rather than a 500;
* keeping `local_evidence` configurable, because reading the filesystem is the difference
  between "a path is outside the workspace" (lexical) and "that directory really holds 14 GB".
"""

from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass, field
from typing import Any

#: Where a checkout can be pointed at, for running against a working copy of the analyzer.
_ANALYZER_SRC = os.environ.get("COMMAND_INSPECTOR_SRC", "")

#: One analyzer per process; construction loads the tree-sitter grammars, which is not free.
_ANALYZERS: dict[bool, Any] = {}


def _ensure_importable() -> None:
    candidates = [_ANALYZER_SRC, os.path.join(_ANALYZER_SRC, "src")] if _ANALYZER_SRC else []
    for candidate in candidates:
        if os.path.isdir(candidate) and candidate not in sys.path:
            sys.path.insert(0, candidate)


def configure(analyzer_src: str) -> None:
    """Point at a working copy of the analyzer.

    Called by `server.py` for `--analyzer`. It sets the environment variable so that anything
    importing this module later — a test process, a probe script — sees the same location, and it
    re-runs the import so a server launched with a flag behaves identically to one launched with
    the variable already set.
    """
    global _ANALYZER_SRC, Analyzer, AnalyzerConfig, LocalEvidenceProvider, EvidenceEffort
    global DisabledEvidenceProvider, _IMPORT_ERROR
    _ANALYZER_SRC = analyzer_src
    os.environ["COMMAND_INSPECTOR_SRC"] = analyzer_src
    _ensure_importable()
    _ANALYZERS.clear()
    Analyzer = _optional("Analyzer", ("command_inspector",))
    AnalyzerConfig = _optional("AnalyzerConfig", ("command_inspector", "command_inspector.config"))
    LocalEvidenceProvider = _optional("LocalEvidenceProvider", ("command_inspector.local_evidence",))
    DisabledEvidenceProvider = _optional("DisabledEvidenceProvider", ("command_inspector.local_evidence",))
    EvidenceEffort = _optional("EvidenceEffort",
                               ("command_inspector", "command_inspector.effort", "command_inspector.local_evidence"))
    _IMPORT_ERROR = None if Analyzer is not None and AnalyzerConfig is not None else _MISSING


#: Why a symbol could not be resolved, filled in by `_optional`.
_MISSING: str | None = None


def _optional(name: str, modules: tuple[str, ...]) -> Any:
    """Resolve `name` from the first module that has it, or None.

    The analyzer has reorganised its modules once already (flat `command_inspector.syntax` became
    the `bash/`-`pwsh/`-`cmd/`-`python/` subpackages in 1.9.0). Hard-coding one path means every
    such move is a crash. Trying a list of candidates, including the package root, keeps the judge
    working across a layout change; `tools/map_new_package.py` prints where everything lives now.
    """
    global _MISSING
    for module_name in modules:
        try:
            module = importlib.import_module(module_name)
        except ImportError as error:
            _MISSING = f"{error.__class__.__name__}: {error}"
            continue
        member = getattr(module, name, None)
        if member is not None:
            return member
    if _MISSING is None:
        _MISSING = f"{name} not found in {', '.join(modules)}"
    return None


_ensure_importable()

Analyzer = _optional("Analyzer", ("command_inspector",))
AnalyzerConfig = _optional("AnalyzerConfig", ("command_inspector", "command_inspector.config"))
LocalEvidenceProvider = _optional("LocalEvidenceProvider", ("command_inspector.local_evidence",))
DisabledEvidenceProvider = _optional("DisabledEvidenceProvider", ("command_inspector.local_evidence",))
EvidenceEffort = _optional("EvidenceEffort",
                           ("command_inspector", "command_inspector.effort", "command_inspector.local_evidence"))
_IMPORT_ERROR: str | None = None if Analyzer is not None and AnalyzerConfig is not None else _MISSING


# ── 本地证据的三层强度 ──────────────────────────────────────────────────────
#
# 1.9.0 把"要不要读文件系统"从一个布尔量变成了三档 `EvidenceEffort`，而且是**每个入口的一等
# 参数**（`analyze(..., effort=)`），不再靠换 evidence provider 来表达。三档的差别见 README：
#
# * `Full`    —— 有界内容读取、元数据、通配符选择/删除统计；
# * `Partial` —— 只查存在性/类型/执行属性/数量，不读内容、不给字节数；
# * `None`    —— 完全不查文件系统，只剩语法、字面量与词法位置规则。
#
# **判定器一律传 `Full`。** 这个参数在分析器内部主要用来在"读取脚本内容去分析"时逐级降档，
# 从而避免一个脚本引自己造成循环引用；判定器是单次调用、每次从零开始，没有这个需求。
# 唯一例外是判定器自己有理由关掉磁盘证据的时候 —— bash 在 Windows 上的混合环境（命令按文本
# 判断，但路径要在另一个文件树里解析，读了就会描述错的文件系统），那里传 `None`。

#: 判定器默认的证据强度。
DEFAULT_EFFORT = "Full"


def normalise_effort(effort: Any = None, *, local_evidence: bool = True) -> str:
    """把各种写法归一成 `Full` / `Partial` / `None`。

    默认 `Full`。接受 `EvidenceEffort` 成员、它的字符串值（大小写不敏感）以及 `True`/`False`。
    认不出来的按默认处理 —— 判定器不该因为一个拼错的参数就悄悄降低证据强度。
    """
    if effort is None:
        return DEFAULT_EFFORT if local_evidence else "None"
    if isinstance(effort, bool):
        return DEFAULT_EFFORT if effort else "None"
    if EvidenceEffort is not None and isinstance(effort, EvidenceEffort):
        return str(effort.value)
    text = str(effort).strip()
    for candidate in ("Full", "Partial", "None"):
        if text.casefold() == candidate.casefold():
            return candidate
    return DEFAULT_EFFORT


def capabilities() -> dict[str, Any]:
    return {"available": False, "error": _IMPORT_ERROR}


@dataclass(frozen=True)
class AnalysisOutcome:
    """What the analyzer said, or why it could not say anything."""

    level: str = "NONE"
    findings: tuple[dict[str, Any], ...] = ()
    unavailable_reason: str | None = None
    analyzer_version: str = ""
    catalog_version: str = ""

    @property
    def reached(self) -> bool:
        return self.unavailable_reason is None

    def rule_names(self) -> tuple[str, ...]:
        return tuple(str(finding.get("rule", "")) for finding in self.findings)


def _analyzer():
    """The shared analyzer instance, or None when it cannot be built.

    Evidence strength is a **per-call** argument in 1.9.0, not a property of the instance, so one
    instance serves every effort level. The analyzer constructs its tree-sitter frontends in
    `__init__`, and the PowerShell grammar is an optional dependency: on a machine that has only
    the bash grammar that constructor raises `FrontendUnavailable`, so it is caught here and
    reported as "analyzer-missing" rather than reaching the HTTP handler as a 500.
    """
    if Analyzer is None or AnalyzerConfig is None:
        return None
    if "instance" not in _ANALYZERS:
        try:
            # 默认 provider；证据强度由每次调用的 `effort=` 决定。
            _ANALYZERS["instance"] = Analyzer(AnalyzerConfig())
        except Exception as error:
            # `FrontendUnavailable` for a missing grammar, `ConfigurationError` for a bad config.
            _ANALYZERS["instance"] = None
            _ANALYZERS["error"] = f"{error.__class__.__name__}: {error}"
    return _ANALYZERS["instance"]


def _analyzer_error() -> str | None:
    """Why the analyzer could not be built, if it could not."""
    return _ANALYZERS.get("error")


def _outcome_from_report(report: Any) -> AnalysisOutcome:
    """One analyzer report -> `AnalysisOutcome`."""
    payload = report.to_dict()
    return AnalysisOutcome(
        level=payload.get("level", "NONE"),
        findings=tuple(payload.get("findings", ())),
        analyzer_version=payload.get("analyzer_version", ""),
        catalog_version=payload.get("rule_catalog_version", ""),
    )


def analyze_command(command: str, cwd: str, *, shell: str,
                    local_evidence: bool = True, effort: Any = None,
                    workspace_root: str | None = None) -> AnalysisOutcome:
    """Analyse one shell command. Never raises for analyzer-side problems.

    `cwd` 是**解析基准**（命令里的相对路径落在哪）；`workspace_root` 是**工作区边界**
    （"有没有脱离用户指定的目录"）。插件把两件事分开送了：`cwd` 是当前目录（`working_directory`
    可以把会话挪走），`working_space` 是用户最初指定的项目、不会变。分析器 1.10.0 起支持
    `workspace_root=`；老版本传不了就退回"边界 = cwd"。
    """
    if _IMPORT_ERROR is not None:
        return AnalysisOutcome(unavailable_reason=f"analyzer-missing ({_IMPORT_ERROR})")
    instance = _analyzer()
    if instance is None:
        reason = _analyzer_error()
        return AnalysisOutcome(unavailable_reason=f"analyzer-missing ({reason})" if reason else "analyzer-missing")
    level = normalise_effort(effort, local_evidence=local_evidence)
    try:
        try:
            report = instance.analyze_report(command, cwd, shell=shell, effort=level,
                                             workspace_root=workspace_root or cwd)
        except TypeError:
            # 老版本分析器没有 `workspace_root`：退回旧行为，不要因此崩掉。
            report = instance.analyze_report(command, cwd, shell=shell, effort=level)
    except Exception as error:  # InputError for a bad cwd, AnalysisError for an internal failure
        return AnalysisOutcome(unavailable_reason=f"{error.__class__.__name__}: {error}")
    return _outcome_from_report(report)


def analyze_sql(sql: str, dialect: str | None = None, *,
                local_evidence: bool = True, effort: Any = None) -> AnalysisOutcome:
    """Analyse SQL text that was not reached through a shell command."""
    if _IMPORT_ERROR is not None:
        return AnalysisOutcome(unavailable_reason=f"analyzer-missing ({_IMPORT_ERROR})")
    instance = _analyzer()
    if instance is None:
        return AnalysisOutcome(unavailable_reason="analyzer-missing")
    entry = getattr(instance, "analyze_sql_report", None)
    if entry is None:
        return AnalysisOutcome(unavailable_reason="analyzer has no analyze_sql_report")
    level = normalise_effort(effort, local_evidence=local_evidence)
    try:
        # 1.9.0 的签名是 `analyze_sql_report(sql, *, dialect=None, effort=...)`，两者都只能按关键字传。
        report = entry(sql, dialect=dialect, effort=level)
    except TypeError:
        # 更老的版本没有 `effort` 参数。
        try:
            report = entry(sql, dialect=dialect)
        except TypeError:
            try:
                report = entry(sql)
            except Exception as error:
                return AnalysisOutcome(unavailable_reason=f"{error.__class__.__name__}: {error}")
        except Exception as error:
            return AnalysisOutcome(unavailable_reason=f"{error.__class__.__name__}: {error}")
    except Exception as error:
        return AnalysisOutcome(unavailable_reason=f"{error.__class__.__name__}: {error}")
    return _outcome_from_report(report)


def analyze_python_source(source: str, cwd: str, *,
                          local_evidence: bool = True, effort: Any = None) -> AnalysisOutcome:
    """Analyse a whole Python source file's text.

    1.9.0 有了直接入口 `analyze_python_report`，所以判定器不必再借道
    `DetectorContext.inspect(..., language="python")`。这条路径还会带上分析器自己的
    文件/路径/流效果模型。
    """
    if _IMPORT_ERROR is not None:
        return AnalysisOutcome(unavailable_reason=f"analyzer-missing ({_IMPORT_ERROR})")
    instance = _analyzer()
    if instance is None:
        return AnalysisOutcome(unavailable_reason="analyzer-missing")
    entry = getattr(instance, "analyze_python_report", None)
    if entry is None:
        return AnalysisOutcome(unavailable_reason="analyzer has no analyze_python_report")
    try:
        report = entry(source, cwd, effort=normalise_effort(effort, local_evidence=local_evidence))
    except Exception as error:
        return AnalysisOutcome(unavailable_reason=f"{error.__class__.__name__}: {error}")
    return _outcome_from_report(report)


# ── 内容分析：直接调分析器的内容入口 ────────────────────────────────────────
#
# `write` / `edit` 要检查的是**文件内容**，不是某条命令。以前这里把内容包成
# `printf %s '…' > '…'` 交给 shell 分析器，后果有二：
#
# * 包装只有 bash 懂。`.ps1` / `.bat` / `.py` 的内容被当 bash 解析，卡片上出现
#   `包含未知命令 printf`、`包含未知命令 def` —— 那是包装命令和 Python 语法，不是用户写的内容；
# * 分析器把**命令**的未解析值贴到了**内容**上。
#
# 分析器自己就有内容入口：`DetectorContext.inspect(text, language, source, context, cwd, depth)`，
# 内部按 `shell` / `powershell` / `cmd` / `python` / `sql` 分派到各自的前端与 builder，并且
# 在 `context == "written_content"` 时把 Python 语法错误报成 `written-source-syntax-error`。
#
# **前端要按需构造。** PowerShell / cmd 的 tree-sitter 语法包是可选依赖，在只装了 bash 的
# 机器上（常见于 Linux）`PowerShellFrontend()` 的**构造**就抛 `FrontendUnavailable`。所以：
#
# * 用 `importlib.util.find_spec` 先看语法包在不在，不在就不去构造 —— 不靠捕异常来探测；
# * 即便包在、构造仍失败，也单独捕获，把那个前端记为不可用而不是让整条链崩掉；
# * 分析 `.py` / `.sh` 时根本不碰 Windows 前端，所以那些包缺失不该有影响。

#: 语法包（distribution 名）-> 分析器里对应的前端。
_FRONTEND_MODULES: dict[str, str] = {
    "bash": "tree_sitter_bash",
    "powershell": "tree_sitter_powershell",
    "cmd": "tree_sitter_powershell",
    "javascript": "tree_sitter_javascript",
}

_CONTENT_CONTEXT: dict[str, Any] = {}


def _grammar_available(module: str) -> bool:
    """那个 tree-sitter 语法包装了没有？只查规格，不导入、不构造。"""
    import importlib.util

    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _build_frontends() -> tuple[dict[str, Any], Any, str | None]:
    """按可用性构造内容分析需要的前端。

    返回 `(windows 前端字典, bash 前端, bash 不可用的原因)`。**任何前端缺失都不抛异常** ——
    缺的那个不进字典，调用方查不到就报 `analysis-unavailable`，其余语言照常工作。

    前端类通过 `_optional` 解析，所以分析器再搬动模块位置也不会在这里崩。
    """
    FrontendUnavailable = _optional("FrontendUnavailable", (
        "command_inspector.bash.syntax", "command_inspector.pwsh.syntax", "command_inspector",
    ))
    bash_class = _optional("BashFrontend", ("command_inspector.bash.syntax", "command_inspector.api"))
    powershell_class = _optional("PowerShellFrontend", ("command_inspector.pwsh.syntax", "command_inspector.api"))
    cmd_class = _optional("CmdFrontend", ("command_inspector.cmd.syntax", "command_inspector.api"))
    # `javascript` 是 1.10.0 新增的第六门前端（`command_inspector.javascript.syntax`）。它只在
    # `structural` 里参与**内容**分析：`DetectorContext.inspect` 用 `self.frontends["javascript"]`
    # 取它，所以必须放进同一个字典。
    javascript_class = _optional("JavaScriptFrontend", ("command_inspector.javascript.syntax",))
    # 前端构造失败的原因不止一种（语法包缺失、grammar ABI 不匹配…），统一按"该前端不可用"处理：
    # 内容是只读输入，拿不到解析器就降级成一条说明，绝不让判定器崩掉。
    frontend_errors = (FrontendUnavailable,) if isinstance(FrontendUnavailable, type) else ()

    windows: dict[str, Any] = {}
    for name, frontend_class, module in (
        ("powershell", powershell_class, _FRONTEND_MODULES["powershell"]),
        ("cmd", cmd_class, _FRONTEND_MODULES["cmd"]),
        ("javascript", javascript_class, _FRONTEND_MODULES["javascript"]),
    ):
        if frontend_class is None or not _grammar_available(module):
            continue
        try:
            windows[name] = frontend_class()
        except frontend_errors or Exception:
            pass

    bash = None
    bash_error: str | None = None
    if bash_class is None:
        bash_error = "BashFrontend not found in this analyzer build"
    elif not _grammar_available(_FRONTEND_MODULES["bash"]):
        bash_error = f"{_FRONTEND_MODULES['bash']} is not installed"
    else:
        try:
            bash = bash_class()
        except frontend_errors or Exception as error:
            bash_error = f"{error.__class__.__name__}: {error}"
    return windows, bash, bash_error


def _content_context(cwd: str):
    """构造一个只用于内容分析、不含命令的检测上下文；失败返回 (None, 原因)。"""
    if "bundle" in _CONTENT_CONTEXT:
        return _CONTENT_CONTEXT["bundle"], _CONTENT_CONTEXT.get("error")
    DetectorContext = _optional("DetectorContext", ("command_inspector.detectors", "command_inspector.api"))
    CachedEvidenceProvider = _optional("CachedEvidenceProvider", ("command_inspector.local_evidence",))
    provider_class = _optional("LocalEvidenceProvider", ("command_inspector.local_evidence",))
    missing = [name for name, value in (("DetectorContext", DetectorContext),
                                        ("CachedEvidenceProvider", CachedEvidenceProvider),
                                        ("LocalEvidenceProvider", provider_class)) if value is None]
    if missing:
        _CONTENT_CONTEXT["bundle"] = None
        _CONTENT_CONTEXT["error"] = f"analyzer-internals-missing: {', '.join(missing)}"
        return None, _CONTENT_CONTEXT["error"]
    windows, bash, bash_error = _build_frontends()
    _CONTENT_CONTEXT["bundle"] = {
        "DetectorContext": DetectorContext,
        "CachedEvidenceProvider": CachedEvidenceProvider,
        "LocalEvidenceProvider": provider_class,
        "frontends": windows,
        "bash": bash,
    }
    _CONTENT_CONTEXT["error"] = None
    _CONTENT_CONTEXT["bash_error"] = bash_error
    return _CONTENT_CONTEXT["bundle"], None


#: 判定器用的语言名 -> 分析器 `inspect()` 认识的语言名。判定器说 `bash`，分析器说 `shell`。
_ANALYZER_LANGUAGE = {"bash": "shell", "sh": "shell", "powershell": "powershell", "cmd": "cmd",
                      "python": "python", "javascript": "javascript", "sql": "sql"}


def _path_style_shell(path: str) -> str:
    """`DetectorContext` 的 `shell=` 是**路径风格选择器**，不是语言名。

    它只被 `style_for(shell, cwd)` 用来决定路径按 Windows 还是 POSIX 解析（见
    `command_inspector.paths`），分析器自己的 `api.py` 也只传 `bash`/`powershell`/`cmd`。

    判据是**路径长什么样**，不是语言、也不是 `os.name` —— 盘符形状（`D:\\x`）要 Windows 风格，
    其余走 POSIX。这样同一份代码在 Linux 上分析 `/home/u/a.py`、在 Windows 上分析 `D:\\a.py`
    各自都对，不依赖运行平台。以前这里传的是语言名（`python`/`sql`），会让路径风格落到 POSIX。
    """
    import ntpath

    return "cmd" if ntpath.splitdrive(path)[0] else "bash"


def analyze_content(content: str, language: str, path: str, *, cwd: str,
                    local_evidence: bool = True, effort: Any = None,
                    workspace_root: str | None = None) -> AnalysisOutcome:
    """分析一段**文件内容**（write/edit 用），不经过命令层。

    `language` 是判定器的叫法（`bash`/`powershell`/`cmd`/`python`），内部翻成分析器的叫法。
    `path` 会作为 finding 的 `source`，所以卡片上指向真实文件。

    `cwd` 是**解析基准**（内容里的相对路径按它解析）；`workspace_root` 是**工作区边界**
    （判断"在不在工作区内"时用它）。两者分开是 1.10.0 新增的能力（`DetectorContext` 的
    `workspace_root=`）：判定器写文件时，相对路径要按文件所在目录解析，但"有没有脱离用户指定的
    目录"必须按会话工作区判。传 `None` 时分析器退回旧行为（边界 = `cwd`）。

    Python 走 `DetectorContext.inspect(..., context="written_content")`，**不用**顶层的
    `analyze_python` 入口。两者语义不同：`written_content` 会把语法错误报成
    `written-source-syntax-error`（"写进文件的内容有语法错"），而直接分析一段源码报的是
    `unsupported-syntax`。write/edit 的场景是前者，README 也把 authored `.py` 文件归在
    written content 一类。
    """
    if _IMPORT_ERROR is not None:
        return AnalysisOutcome(unavailable_reason=f"analyzer-missing ({_IMPORT_ERROR})")
    if AnalyzerConfig is None:
        return AnalysisOutcome(unavailable_reason="analyzer-missing")
    analyzer_language = _ANALYZER_LANGUAGE.get(language)
    if analyzer_language is None:
        return AnalysisOutcome(unavailable_reason=f"unsupported content language: {language}")
    level = normalise_effort(effort, local_evidence=local_evidence)

    bundle, error = _content_context(cwd)
    if bundle is None:
        return AnalysisOutcome(unavailable_reason=f"analyzer-internals-missing ({error})")
    # 先确认这门语言的前端真的可用，缺了就直说，而不是构造到一半崩掉。
    if analyzer_language == "shell" and bundle["bash"] is None:
        return AnalysisOutcome(
            unavailable_reason=f"content-frontend-unavailable (bash: {_CONTENT_CONTEXT.get('bash_error')})"
        )
    if analyzer_language in {"powershell", "cmd", "javascript"} and analyzer_language not in bundle["frontends"]:
        module = _FRONTEND_MODULES[analyzer_language]
        return AnalysisOutcome(
            unavailable_reason=f"content-frontend-unavailable ({analyzer_language}: {module} is not installed)"
        )
    config = AnalyzerConfig()
    provider = bundle["CachedEvidenceProvider"](
        bundle["LocalEvidenceProvider"](), config.total_read_bytes, config.directory_entries
    )
    keywords = dict(shell=_path_style_shell(path), frontends=bundle["frontends"], effort=level)
    try:
        # 老版本分析器没有 `workspace_root`：那样边界只能是 `cwd`（旧行为），不能因此崩掉。
        if workspace_root:
            context = bundle["DetectorContext"](
                config, cwd, {}, provider, bundle["bash"], "",
                workspace_root=workspace_root, **keywords,
            )
        else:
            context = bundle["DetectorContext"](
                config, cwd, {}, provider, bundle["bash"], "", **keywords,
            )
    except TypeError:
        context = bundle["DetectorContext"](
            config, cwd, {}, provider, bundle["bash"], "", **keywords,
        )
    try:
        # `written_content` 是"这段文本是被写进文件的内容"这个上下文，正是 write/edit 的情形。
        context.inspect(content, analyzer_language, path, "written_content", cwd, 0)
    except Exception as error:
        # 前端在解析中途抛 `FrontendUnavailable` 也算"这门语言查不了"，不该让判定器崩掉。
        return AnalysisOutcome(unavailable_reason=f"{error.__class__.__name__}: {error}")
    return AnalysisOutcome(findings=tuple(finding.to_dict() for finding in context.findings))


def capabilities() -> dict[str, Any]:
    if Analyzer is None:
        return {"available": False, "error": _IMPORT_ERROR}
    instance = _analyzer()
    if instance is None:
        return {"available": False, "error": _analyzer_error() or "analyzer-missing"}
    payload = instance.capabilities()
    return {"available": True, "effort": DEFAULT_EFFORT, **payload}


def rule_catalog() -> dict[str, Any]:
    if Analyzer is None:
        return {"rules": []}
    instance = _analyzer()
    return instance.rule_catalog() if instance else {"rules": []}


def rule_names() -> tuple[str, ...]:
    """Every rule name the analyzer publishes, for coverage checks and `/healthz`."""
    return tuple(str(entry.get("rule", "")) for entry in rule_catalog().get("rules", []))
