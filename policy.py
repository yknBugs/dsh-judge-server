"""The decision policy: which tool gets approve, ask or deny, and what the card says.

Read this module as the answer to "what happens for tool X". The families come from `tools.py`;
the wording comes from `rules_zh.py`; the analysis comes from the analyzer. Nothing here guesses
a platform or a dialect.

One rule runs through all of it: **approve is only ever returned when a check actually ran and
found nothing**, or when the tool provably cannot change state. A skipped check is an ask.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from analyzer_link import analyze_command
from filechecks import check_edit, check_write, is_absolute_path, resolve_path, within_workspace
from localmodel import enabled as model_enabled, note_for
from readchecks import check_read
from rules_zh import INFORMATIONAL, JUDGE_ERROR_RULE, LEVEL_ORDER, label_for
from tools import ToolPolicy, policy_for, shell_dialect
from writers import Finding, render

CLEAN = "本次调用未发现风险。"

#: 自动批准到哪一级。判定器不再用"要不要每条都问"这个布尔量，而是给一个**等级上限**：
#: 发现里最严重的那条不超过这个上限就自动放行，超过就交给人工。
#:
#: 五个名字对应命令行参数，数值用 `LEVEL_ORDER` 的刻度（NONE=0 … BLOCK=4）：
#:
#: | 参数 | 上限 | 含义 |
#: | --- | --- | --- |
#: | `--always-ask`   | `NEVER`  | 永不自动放行，每条都问（含零发现） |
#: | `--skip-safe`    | `NONE`   | 只自动放行**零发现**的调用（默认） |
#: | `--auto-approve` | `LOW`    | 上限 `[提示]` |
#: | `--report-warning` | `MEDIUM` | 上限 `[注意]` |
#: | `--approve-all`  | `HIGH`   | 上限 `[警告]` |
#:
#: `BLOCK`（`[拦截]`）**不在任何上限之内**：它是判定器唯一自己的 deny，任何参数都不会把它
#: 变成放行。`--approve-all` 的"all"到 `[警告]` 为止就是这个意思。
AUTO_APPROVE_NEVER = -1
AUTO_APPROVE_NONE = 0

#: 参数名 -> 等级上限。命令行解析与文档都读它，避免两处各写一遍。
AUTO_APPROVE_LEVELS: dict[str, int] = {
    "always-ask": AUTO_APPROVE_NEVER,
    "skip-safe": AUTO_APPROVE_NONE,
    "auto-approve": 1,       # LEVEL_ORDER["LOW"]
    "report-warning": 2,     # LEVEL_ORDER["MEDIUM"]
    "approve-all": 3,        # LEVEL_ORDER["HIGH"]
}

#: 默认上限：`--skip-safe`。
AUTO_APPROVE = AUTO_APPROVE_NONE


def normalise_auto_approve(value: Any = None) -> int:
    """把各种写法归一成等级上限（整数）。

    接受：`None`（用默认）、参数名（`"skip-safe"`、`"--auto-approve"`）、等级名
    （`"LOW"`）、整数上限、以及旧的布尔（`True` -> `NEVER`，`False` -> `NONE`）。
    """
    if value is None:
        return AUTO_APPROVE
    if isinstance(value, bool):
        # 兼容旧调用：`auto_approve=True` 就是"永不自动放行"。
        return AUTO_APPROVE_NEVER if value else AUTO_APPROVE_NONE
    if isinstance(value, int):
        return value
    text = str(value).strip().lstrip("-").casefold()
    if text in AUTO_APPROVE_LEVELS:
        return AUTO_APPROVE_LEVELS[text]
    if text.upper() in LEVEL_ORDER:
        return LEVEL_ORDER[text.upper()]
    return AUTO_APPROVE


@dataclass
class Decision:
    decision: str
    reason: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "reason": self.reason}


def _line(index: int, level: str, text: str) -> str:
    """卡片的一行。判定器只加"序号. [等级] "这一段，后面全部由 writers.py 决定。"""
    return f"{index}. [{label_for(level)}] {text}"


def _conclude(findings: list[dict[str, Any]], context: tuple[str, dict, str], auto_approve: bool) -> Decision:
    """The single place that turns findings into a decision.

    The local model is consulted HERE and only here, and only when there is something to report.
    That ordering is the point: this judge does not fail silently — an unreadable command arrives
    as `unknown-command`, an unresolved operand as `unresolved-value`, a crashed check as
    `analyzer-error` — so a call with no findings was genuinely understood and found clean.
    Spending a model call on it, and putting a note on a card that is about to be auto-approved,
    would be paying for nothing.

    `context` is ``(tool, args, cwd)``, used only for the advisory prompt.
    """
    if not findings:
        return _clean_decision(auto_approve)
    note = ""
    if model_enabled():
        tool, args, cwd = context
        try:
            note = note_for(tool, args, cwd)
        except Exception:
            # Advisory only: a model that misbehaves must not affect the verdict or crash a card.
            note = ""
    return _decide_from_findings(findings, auto_approve, note)


#: First token of a command that is unmistakably another shell's. Used only to notice that the
#: tool name and the command text disagree — a real situation on Windows, where a bash tool can
#: be handed PowerShell text — so the mismatch is named instead of becoming a pile of
#: "unsupported syntax" lines.
_FOREIGN_SHELL_MARKERS = {
    "bash": re.compile(
        r"(?i)^(get-childitem|remove-item|set-content|get-content|start-process|stop-process|"
        r"new-item|copy-item|move-item|invoke-webrequest|iex|set-executionpolicy|schtasks|reg\s|"
        r"icacls|taskkill|vssadmin|wevtutil|diskpart)\b"
    ),
    "powershell": re.compile(
        r"(?i)^(rm\s|rd\s|rmdir\s|del\s|erase\s|chmod\s|chown\s|sudo\s|apt-get\s|systemctl\s|"
        r"ifconfig\s|killall\s|pkill\s|umount\s|cat\s)"
    ),
    "cmd": re.compile(r"(?i)^(rm\s|chmod\s|chown\s|apt-get\s|systemctl\s|umount\s|pkill\s|cat\s)"),
}


def _render_findings(findings: list[dict[str, Any]]) -> str:
    """One line per finding, most severe first.

    The line's content is entirely `writers.py`'s: a writer returns the whole text, and only the
    `序号. [等级] ` prefix is added here. Deduplication is therefore on the writer's own text,
    with no judge-side structure to reconcile.
    """
    lines = []
    for index, entry in enumerate(_merge(findings), 1):
        text, level, count = entry
        if count > 1:
            # 插在**最后一个句号之前**，不是整句之后。
            #
            # 追加到末尾的话，若句子已经以附注收尾（`…完整检查。可能的值：F 可能为 a 或 b。`），
            # 后缀会落在那个句号后面，读起来像两句：`…可能的值：…。（共 2 处）`。
            # 放在末句句号前就自然了：`可能的值：F 可能为 a 或 b（共 2 处）。`
            suffix = f"（共 {count} 处）"
            text = f"{text[:-1]}{suffix}。" if text.endswith("。") else f"{text}{suffix}"
        lines.append(_line(index, level, text))
    return "\n".join(lines)


def _merge(findings: list[dict[str, Any]]) -> list[tuple[str, str, str, int]]:
    """One entry per distinct RENDERED line, most severe first, with its count.

    The rule: an occurrence is dropped only when the line that would be printed for it cannot be
    told apart from a line already printed. Duplication is a property of the CARD, not of the
    findings — two findings that render differently are both worth showing, and two that render
    identically have nothing to add to each other.

    That is why the wording matters so much. While `unresolved-value` said only "an argument
    depends on runtime", a directory listing and a file read produced the same sentence and the
    card looked broken. Once the sentence names the operation, those two no longer collide.

    The wording is entirely `writers.py`'s business: a writer may take the analyzer's condition
    into account (`Finding.condition_text()`), and if it does, lines differing by condition stay
    separate. This function does not add anything of its own — what the writer returns is the line.

    The LEVEL is deliberately not part of the key. Two findings that read identically but are
    labelled differently would print the same sentence twice under two different labels, which is
    the confusion this rule exists to prevent. The list is sorted by severity, so the stronger
    occurrence survives — a weaker restatement of the same finding cannot make a call safer than
    the stronger one already made it.
    """
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for finding in sorted(findings, key=lambda f: -LEVEL_ORDER.get(str(f.get("level", "LOW")).upper(), 1)):
        level = str(finding.get("level", "LOW")).upper()
        # 文案一律来自 writers.py。这里不再有"检查代码自己写句子"的分支——`filechecks` 与
        # `readchecks` 只产出规则名、等级和数据，句子与它们分开了。
        text = render(finding)
        if text not in merged:
            merged[text] = {"count": 0, "level": level}
            order.append(text)
        merged[text]["count"] += 1
    return [(text, merged[text]["level"], merged[text]["count"]) for text in order]


def _clean_decision(auto_approve: int = AUTO_APPROVE_NONE) -> Decision:
    """零发现时的判定。

    * 上限 >= `NONE`（默认 `--skip-safe`）—— **APPROVE**。分析器不会静默：读不懂的命令会
      报 `unknown-command` / `unsupported-syntax`，取值不定报 `unresolved-value`，判定器自己
      检查不了会报 `analyzer-error`。所以"没有发现"意味着这次调用被理解且没看到问题。
    * 上限是 `NEVER`（`--always-ask`）—— **ASK**，文案仍是 `本次调用未发现风险。`，
      让读者知道它为什么被展示。
    """
    if auto_approve < AUTO_APPROVE_NONE:
        return Decision("ask", CLEAN, [])
    return Decision("approve", CLEAN, [])


def _model_block(note: str) -> str:
    """The advisory note, labelled so it cannot be mistaken for a found fact."""
    return f"【本地模型补充（仅供参考，不参与判定）】\n{note}"


def _decide_from_findings(findings: list[dict[str, Any]], auto_approve: int = AUTO_APPROVE_NONE,
                          note: str = "") -> Decision:
    """发现 -> 判定。

    只有统计类发现（写了多少字节、文件没变）时仍按上限走；有实质发现时取最严重的那条，
    与上限比较：

    * 最严重 > 上限 -> **ASK**（交给人工）；
    * 最严重 <= 上限 -> **APPROVE**（自动放行，但文案照旧列出发现——"放行"不等于"不告诉你"）。

    `BLOCK`（`[拦截]`）例外：它是判定器唯一的 deny，不受上限影响。
    """
    if not findings:
        return _clean_decision(auto_approve)
    decisive = [f for f in findings if str(f.get("rule", "")) not in INFORMATIONAL]
    if not decisive:
        # 只有统计类发现：值得**显示**（读者要那些实测数字），但等级上限照样管着它 ——
        # `--always-ask` 下连它也要问（否则"每条都问"就漏了一类）。信息级别按 0 算，
        # 也就是"只要上限 >= NONE 就放行"。
        rendered = _render_findings(findings)
        if not rendered:
            return _clean_decision(auto_approve)
        decision = "approve" if auto_approve >= AUTO_APPROVE_NONE else "ask"
        return Decision(decision, rendered, findings)
    worst = max((LEVEL_ORDER.get(str(f.get("level", "LOW")).upper(), 1) for f in decisive), default=0)
    # The four labels map to the three decisions: only the analyzer's own BLOCK 拦截 denies;
    # 警告/注意/提示 all reach a human with the list in front of them。
    if worst >= LEVEL_ORDER["BLOCK"]:
        decision = "deny"
    else:
        decision = "approve" if worst <= auto_approve else "ask"
    reason = _render_findings(findings)
    if note:
        reason = f"{reason}\n\n{_model_block(note)}"
    return Decision(decision, reason, findings)


def _judge_error(reason: str) -> dict[str, Any]:
    """分析器未能完成检查，作为一等 finding 报出来，而不是让服务崩掉。

    句子由 `writers.py` 的 `w_analyzer_error` 生成，这里给原因。
    """
    return {"rule": JUDGE_ERROR_RULE, "level": "MEDIUM", "data": {"reason": reason}, "evidence": []}


def _posix_cwd(cwd: str) -> str:
    """A cwd the bash frontend accepts, derived from a drive path when necessary.

    `D:\\Temp\\x` is POSIX-shaped nowhere, and the analyzer refuses it for bash rather than
    guessing. `D:\\Temp\\x` becomes `/d/Temp/x`, which is what MSYS/Cygwin actually hands a POSIX
    shell for that directory — so the command is analysed against a plausible cwd instead of
    being reported as an analyzer failure.
    """
    if len(cwd) >= 2 and cwd[1] == ":":
        rest = cwd[2:].replace("\\", "/").lstrip("/")
        return f"/{cwd[0].lower()}/{rest}" if rest else f"/{cwd[0].lower()}"
    return cwd if cwd.startswith("/") else "/"


def _windows_cwd(cwd: str) -> str:
    """A cwd the powershell/cmd frontends accept."""
    return cwd if (len(cwd) >= 2 and cwd[1] == ":") else "C:\\"


def _shell_decision(tool: str, args: dict, cwd: str, workspace: str = "",
                    auto_approve: bool = False) -> Decision:
    boundary = workspace or cwd
    dialect = shell_dialect(tool) or "bash"
    command = args.get("command") or args.get("cmd") or args.get("script") or ""
    if not isinstance(command, str) or not command.strip():
        # Nothing to analyse. Not a clean result: there was no result.
        return Decision("ask", CLEAN)

    # The tool name and the command text can disagree — a `bash` tool handed PowerShell text, or
    # the reverse. Naming that is far more useful than the pile of "unsupported syntax" findings
    # the parser would otherwise produce, so it is reported first and the analysis still runs.
    mismatch = _FOREIGN_SHELL_MARKERS.get(dialect)
    findings: list[dict[str, Any]] = []
    if mismatch is not None and mismatch.match(command.lstrip()):
        # 文案在 writers.py 的 `w_command_tool_mismatch`，这里只给数据。
        findings.append(
            {"rule": "command-tool-mismatch", "level": "MEDIUM", "data": {"tool": tool}, "evidence": []}
        )

    # A POSIX shell on a Windows host is a mixed environment: the session cwd is a drive path
    # while bash resolves `/` in its own tree. Local evidence would then describe the WRONG
    # filesystem, so it is turned off and the lexical analysis stands on its own.
    evidence = True
    if dialect == "bash":
        target_cwd = _posix_cwd(cwd)
        target_workspace = _posix_cwd(boundary)
        evidence = not (len(cwd) >= 2 and cwd[1] == ":")
    else:
        target_cwd = _windows_cwd(cwd)
        target_workspace = _windows_cwd(boundary)

    outcome = analyze_command(command, target_cwd, shell=dialect, local_evidence=evidence,
                              workspace_root=target_workspace)
    if not outcome.reached:
        # The shell/dialect combination itself was rejected. That is information about the call,
        # not a crash, and it is reported as such.
        findings.append(_judge_error(str(outcome.unavailable_reason)))
        return _conclude(findings, (tool, args, cwd), auto_approve)
    findings.extend(dict(finding) for finding in outcome.findings)
    if dialect == "bash" and not evidence:
        findings.extend(_outside_workspace_tokens(command, boundary))
    return _conclude(findings, (tool, args, cwd), auto_approve)


#: Absolute POSIX tokens a bash command names, used only when disk evidence is unavailable.
_POSIX_ABSOLUTE = re.compile(r"(?<![\w.\\/-])(/[A-Za-z0-9._-][^\s\"';|&)<>]*)")


def _outside_workspace_tokens(command: str, workspace: str) -> list[dict[str, Any]]:
    """Bash targets that are absolute and not the workspace — checked lexically.

    With local evidence off, the analyzer cannot compare a target against the workspace, so the
    reach check is done here on the text. This is the one place the judge reads tokens itself,
    and it is deliberately confined to "is this absolute path under the workspace", which is a
    lexical question with a definite answer.
    """
    workspace_posix = _posix_cwd(workspace).rstrip("/")
    hits: list[str] = []
    for match in _POSIX_ABSOLUTE.finditer(command):
        token = match.group(1).rstrip(".,;:")
        if token in {"/", "/dev/null"}:
            continue
        if workspace_posix and (token == workspace_posix or token.startswith(workspace_posix + "/")):
            continue
        hits.append(token)
    if not hits:
        return []
    return [
        {
            "rule": "delete-outside-workspace" if re.search(r"(?i)\b(rm|rd|rmdir|del|unlink)\b", command) else "write-outside-workspace",
            "level": "MEDIUM",
            "title": "outside",
            "detail": "命令里出现了工作区之外的绝对路径。",
            "data": {"target": "、".join(dict.fromkeys(hits))},
            "evidence": [],
        }
    ]


def _write_decision(tool: str, args: dict, cwd: str, workspace: str = "",
                    auto_approve: bool = False) -> Decision:
    path = args.get("file_path") or args.get("filePath") or args.get("path") or ""
    if not isinstance(path, str) or not path:
        return Decision("ask", CLEAN)
    if tool.lower() == "edit":
        report = check_edit(path, args, cwd, workspace)
    else:
        report = check_write(path, args, cwd, workspace)
    return _conclude(report.findings, (tool, args, cwd), auto_approve)


def _read_decision(tool: str, args: dict, cwd: str, workspace: str = "",
                   auto_approve: bool = False) -> Decision:
    path = args.get("file_path") or args.get("filePath") or args.get("path") or args.get("pattern") or ""
    if not isinstance(path, str) or not path:
        return _clean_decision(auto_approve)
    return _conclude(check_read(tool, path, args, cwd, workspace).findings,
                     (tool, args, cwd), auto_approve)


def _cwd_decision(args: dict, cwd: str, workspace: str = "", auto_approve: bool = False) -> Decision:
    """`working_directory`：改会话工作目录，看新目录有没有跳出**用户指定的工作区**。

    参数是 `{cd?: string}`（见 `dsh-tool-working-directory`）。**省略 `cd` 就只是读**当前目录，
    不动任何状态，直接放行——那和 `get_goal` 是同一类动作。

    给了 `cd` 才要判断：新目录若落在工作区外，后续所有相对路径都会在那个目录下解析，包括删除
    和写入。所以这不能只看成"换个地方"，它改变的是**后面每一步的含义**，等级取 `MEDIUM`，与
    `write-outside-workspace` 同档。

    **两件事必须分开**（插件从 0.2 起分别送）：

    * `cwd` —— 会话**当前**目录。`cd` 的相对路径按它解析，所以 `cd ..` 是从现在的位置往上走；
    * `workspace` —— 用户**最初指定**的目录（`working_space`）。`cd` 的落点跟它比。

    混用会出错：只用 `cwd` 当边界时，`cd` 到子目录后再 `cd ..` 会被误报"跳出"；只用 `workspace`
    当解析基准时，`cd` 相对路径会落错地方。`workspace` 缺省时退回 `cwd`（老插件只发一个值）。

    路径要**先折叠 `..` 再比较**（`resolve_path`）。`within_workspace` 是纯前缀比较，
    `/work/sub/../..` 会被它当成"在区内"，而实际指向 `/`。
    """
    boundary = workspace or cwd
    target = args.get("cd")
    if not isinstance(target, str) or not target.strip():
        # 只读：没有 `cd`（或给了空值）时不改变任何状态。
        return _clean_decision(auto_approve)
    target = target.strip()
    resolved = resolve_path(target, cwd) if not is_absolute_path(target) else resolve_path(target, "")
    if not boundary or within_workspace(resolved, boundary):
        return _clean_decision(auto_approve)
    finding = {
        "rule": "cwd-outside-workspace",
        "level": "MEDIUM",
        "data": {"target": resolved, "cwd": boundary, "requested": target},
        "evidence": [],
    }
    return _decide_from_findings([finding], auto_approve)


def _confirm_decision(tool: str, policy: ToolPolicy, auto_approve: int) -> Decision:
    """参数看不出版本行为的工具 -> 一条 `MEDIUM` 的发现。

    **不是**"无脑 ask"：等级是 `MEDIUM`，所以 `--report-warning` 及以上会放行它。默认
    `--skip-safe` 下照旧要人确认。

    文案就是那一句话（"这个工具在做什么"），不加"该工具需要人工确认"前缀，也不补后果说明：
    那些内容**不随参数变化**，所以不是发现，只是多一行字。
    """
    finding = {
        "rule": "tool-needs-confirmation",
        "level": "MEDIUM",
        "data": {"tool": tool, "note": policy.note},
        "evidence": [],
    }
    return _decide_from_findings([finding], auto_approve)


def _search_decision(tool: str, args: dict, policy: ToolPolicy, auto_approve: int) -> Decision:
    """搜索类 -> 一条 `LOW` 的发现：查询词外发，内容无可审查之处。

    它**不可能零发现**（每次搜索都有一条），但不是盲目的 ask：`--auto-approve` 及以上会放行。

    `queries` 要带上：参数里就有，**知道的信息就写**——没有它这张卡等于只说"会联网"。
    """
    finding = {
        "rule": "search-request",
        "level": "LOW",
        "data": {"tool": tool, "note": policy.note, "queries": args.get("queries")},
        "evidence": [],
    }
    return _decide_from_findings([finding], auto_approve)


def _fetch_decision(args: dict, auto_approve: bool = False) -> Decision:
    url = args.get("url") or args.get("URL") or ""
    if not isinstance(url, str) or not url:
        return Decision("ask", CLEAN)
    heavy, host, alternative = _fetch_shape(url)
    # 两种情况都要人确认：抓取会把远端内容送进模型上下文。等级区分的是"这地址会拿回多少"：
    # 普通页面 `LOW`（值得知道），整页 HTML `MEDIUM`（关键操作：会灌进一大段无用内容）。
    # 句子由 writers.py 的 `w_download_content` / `w_network_request` 生成，靠 `data.fetch_kind` 区分。
    level, rule = ("MEDIUM", "download-content") if heavy else ("LOW", "network-request")
    # `host` **两种情形都带上**：卡片要写"发到哪个站点"，那才是随参数变化的信息。
    data: dict[str, Any] = {"url": url, "fetch_kind": "heavy" if heavy else "page"}
    if host:
        data["host"] = host
    if alternative:
        # 有更省的同源端点时一并给出（`建议用 api.github.com 等替代`）。没有就不编一个。
        data["alternative"] = alternative
    finding = {"rule": rule, "level": level, "data": data, "evidence": []}
    return _decide_from_findings([finding], auto_approve)


#: 会返回大段 HTML 的站点 -> 更省的端点。值是 `None` 表示没有可靠的同源替代端点，那就只说
#: "会返回大段 HTML"，不编一个地址出来。
#:
#: 只收**确定存在**的公开 API：`github.com` 的页面是渲染好的 HTML，`api.github.com` 是 JSON；
#: Stack Overflow 的页面同理，`api.stackexchange.com` 是 JSON；npm 的包页对 `registry.npmjs.org`；
#: Reddit 的 `.json` 后缀是同一份数据。Medium 没有公开的等价 API，所以留 `None`。
_HEAVY_HTML_HOSTS: dict[str, str | None] = {
    "github.com": "api.github.com",
    "stackoverflow.com": "api.stackexchange.com",
    "npmjs.com": "registry.npmjs.org",
    "pypi.org": "pypi.org/pypi",
    "reddit.com": "www.reddit.com/.json",
    "medium.com": None,
}


def _url_host(url: str) -> str:
    """从 URL 里取站点名；取不到返回空串。

    用 `urllib.parse.urlsplit`（纯 Python，不依赖平台）。卡片上写"发到哪个站点"比写一整条 URL
    更容易读，URL 本身仍然在 `data.url` 里。
    """
    from urllib.parse import urlsplit

    try:
        netloc = urlsplit(url if "://" in url else "https://" + url).netloc
    except ValueError:
        return ""
    return netloc.rsplit("@", 1)[-1].split(":")[0].lower()


def _fetch_shape(url: str) -> tuple[bool, str, str]:
    """`(是否整页 HTML, 站点名, 更省的端点)`。

    A raw/API endpoint on a heavy host is not the heavy case — that is the point of the advice.
    A bare host with no path is the front page of a site, which is the heaviest case of all.
    """
    lowered = url.lower()
    host = _url_host(url)
    if any(marker in lowered for marker in ("/raw/", "api.", "raw.githubusercontent", ".json", ".txt", "/releases/download")):
        return False, host, ""
    for heavy_host, alternative in _HEAVY_HTML_HOSTS.items():
        if heavy_host in lowered:
            return True, host or heavy_host, alternative or ""
    if lowered.endswith(("/", ".html", ".htm")):
        return True, host, ""
    # scheme://host with nothing after the host
    if re.fullmatch(r"https?://[^/]+/?", lowered):
        return True, host, ""
    return False, host, ""


#: 请求体里的**上下文**字段。它们不是工具名，扫描"哪个键是工具"时要跳过。
_DOCUMENT_CONTEXT_KEYS = frozenset({"cwd", "working_space", "session_id", "tool", "args"})


def _args_from_pairs(raw: Any) -> dict[str, Any]:
    """`args` 的有序数组 -> 字典。

    插件从 0.2 起把参数发成 `[{"name": "command", "value": "ls"}, …]`（保持调用方自己的顺序，
    也让不合法的参数名能安全通过）。老形状是直接的字典，两种都收。

    条目没有 `name` 的（插件用空名表示"整个 args 不是对象"）会被丢掉——本判定器管的七个工具
    参数都是对象，丢掉的只会是畸形调用，那种情况后面的"缺必要参数"分支会把它变成 `ask`。
    """
    if isinstance(raw, dict):
        return dict(raw)
    if not isinstance(raw, list):
        return {}
    args: dict[str, Any] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if isinstance(name, str) and name:
            args[name] = entry.get("value")
    return args


def document_facts(document: dict[str, Any]) -> tuple[str, dict[str, Any], str, str]:
    """请求体 -> `(工具名, 参数, 当前目录, 用户指定的工作区)`。

    插件 0.2 起发的默认文档是：

        {"session_id": …, "working_space": …, "cwd": …, "tool": …, "args": [{name, value}, …]}

    `working_space` 和 `cwd` 是**两个不同的问题**，不能合并：

    * `cwd` —— 这次调用**现在**在哪跑（`working_directory` 可以把会话挪走），决定相对路径的含义；
    * `working_space` —— 用户**最初指定**的项目，不会变，决定"有没有跳出工作区"。

    老形状 `{cwd, "<tool>": {…}}` 仍然接受（探针和既有调用方都用它），那种情况下两个值是同一个。
    """
    cwd = document.get("cwd") if isinstance(document.get("cwd"), str) else ""
    workspace = document.get("working_space") if isinstance(document.get("working_space"), str) else ""
    boundary = workspace or cwd

    tool = document.get("tool")
    if isinstance(tool, str) and tool:
        return tool, _args_from_pairs(document.get("args")), cwd, boundary

    for key, value in document.items():
        if key in _DOCUMENT_CONTEXT_KEYS or not isinstance(value, dict):
            continue
        return str(key), value, cwd, boundary
    return "", {}, cwd, boundary


def decide(document: dict[str, Any], auto_approve: Any = None) -> Decision:
    """One plugin request -> one decision.

    ``auto_approve`` 覆盖模块默认值（等级上限，见 `AUTO_APPROVE_LEVELS`）。服务器把它从这里传
    进来，而不是改全局状态，所以调用方可以按请求选择。接受参数名/等级名/整数/旧布尔，
    统一由 `normalise_auto_approve` 归一。

    请求体有两种形状（见 `document_facts`），这里只管分派。
    """
    auto_approve = normalise_auto_approve(auto_approve)
    tool, args, cwd, workspace = document_facts(document)

    if not tool:
        return Decision("ask", CLEAN)

    policy = policy_for(tool)
    if policy.family == "approve":
        # Approved by instruction, and by construction: these cannot change state. `--always-ask`
        # does not override that — there is nothing to be careful about, and the instruction was
        # that they are never inspected.
        return Decision("approve", CLEAN)
    if policy.family == "confirm":
        return _confirm_decision(tool, policy, auto_approve)
    if policy.family == "search":
        return _search_decision(tool, args, policy, auto_approve)
    if policy.family == "shell":
        return _shell_decision(tool, args, cwd, workspace, auto_approve)
    if policy.family == "write":
        return _write_decision(tool, args, cwd, workspace, auto_approve)
    if policy.family == "read":
        return _read_decision(tool, args, cwd, workspace, auto_approve)
    if policy.family == "cwd":
        return _cwd_decision(args, cwd, workspace, auto_approve)
    if policy.family == "fetch":
        return _fetch_decision(args, auto_approve)
    return Decision("ask", f"未知工具「{tool}」：判定器没有它的行为模型，无法代为放行。")
