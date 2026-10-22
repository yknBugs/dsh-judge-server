"""HTTP surface for the judge, matching the manual-approval plugin's judge action.

The plugin POSTs `{"cwd": "...", "<toolName>": {<args>}}` and reads any JSON body at its
configured `decisionPath` / `reasonPath`. Both default to `decision` / `reason`, which is what
this returns.

Loopback by default. A token is optional there and mandatory on any other bind, because an
address reachable from the network without a token is a judge anyone can ask, and a judge is
also a file-existence oracle.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import secrets
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import analyzer_link
from analyzer_link import capabilities, rule_names
from localmodel import ENV_MODEL, ENV_POLICY, ENV_TIMEOUT, ENV_URL, enabled as model_enabled, policy as model_policy
from policy import AUTO_APPROVE_LEVELS, Decision, decide
from rules_zh import known_rules

#: The reason text for a call that was analysed and produced nothing.
CLEAN_VERDICT = "本次调用未发现风险。"

#: Bumped when the DECISION SHAPE changes, not on every edit. Reported by `/healthz` so a
#: long-running process can be asked which behaviour it implements.
#:
#: 1 — clean calls are APPROVED; `--always-ask` asks about them instead. Local model notes are
#:     advisory and only requested when there is a finding.
#: 2 — the auto-approve switch is a **level ceiling** (`--always-ask` / `--skip-safe` /
#:     `--auto-approve` / `--report-warning` / `--approve-all`), not a boolean: a finding is
#:     auto-approved when it is at or below the ceiling. `BLOCK` is never auto-approved.
#: 3 — the REQUEST document shape changed: `{session_id, working_space, cwd, tool, args}`,
#:     where `cwd` is the CURRENT directory and `working_space` the user-designated project.
#:     A judge that only knows the old map shape would silently ask everything, so the number
#:     is bumped to make that queryable from `/healthz`.
DECISION_BEHAVIOUR = 3

MAX_BODY_BYTES = 4 * 1024 * 1024


class JudgeHandler(BaseHTTPRequestHandler):
    server_version = "dsh-judge-server/0.1"
    protocol_version = "HTTP/1.1"

    token: str = ""
    log_verbose: bool = False
    #: 自动批准等级上限（整数，见 `policy.AUTO_APPROVE_LEVELS`），不是布尔。
    auto_approve: int = 0
    #: `--logging`：把每次请求写进 `log/`。
    log_requests: bool = False

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D102 - quieter default
        if self.log_verbose:
            sys.stderr.write("[judge] " + (fmt % args) + "\n")

    def handle_one_request(self) -> None:
        """Read one request, and treat a dropped connection as a non-event.

        A caller that times out closes the socket mid-request, and the base class prints a full
        traceback for it. Nothing was decided and nobody is waiting for the answer, so the only
        effect of logging it is training the reader to ignore the log.
        """
        try:
            super().handle_one_request()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            self.close_connection = True
            if self.log_verbose:
                sys.stderr.write("[judge] client disconnected before the request completed\n")

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.startswith("/healthz"):
            # `behaviour` and the rule counts are the debugging surface: the judge keeps its code
            # and the analyzer in memory from start-up, so "which build is answering, and how many
            # rules does it actually have?" is the first question when something looks stale.
            # `analyzer_loaded` is the count the parser published; `judge_rules` is how many of
            # them this judge has Chinese wording for. They diverge when the analyzer grows.
            caps = capabilities()
            self._send(
                200,
                {
                    "ok": True,
                    "behaviour": DECISION_BEHAVIOUR,
                    "autoApprove": self.auto_approve,
                    "rules": len(rule_names()),
                    "judge_rules": len(known_rules()),
                    "analyzer": caps,
                    "localModel": {
                        "enabled": model_enabled(),
                        "policy": model_policy(),
                    },
                },
            )
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        # Fail towards "ask": a rejection here surfaces as a red warning on the card, never as
        # an allow.
        if self.token and self.headers.get("x-manual-approval-token", "") != self.token:
            self._send(401, {"error": "bad or missing token"})
            return
        try:
            size = int(self.headers.get("content-length", "0"))
        except ValueError:
            self._send(400, {"error": "bad content-length"})
            return
        if size <= 0 or size > MAX_BODY_BYTES:
            self._send(413, {"error": f"body size {size} out of range"})
            return
        raw = self.rfile.read(size)
        try:
            document = json.loads(raw.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            self._send(400, {"error": f"body is not JSON: {error}"})
            return
        if not isinstance(document, dict):
            self._send(400, {"error": "body must be a JSON object"})
            return
        try:
            result = decide(document, auto_approve=self.auto_approve)
        except Exception:  # last resort; the plugin would warn anyway, but be explicit
            detail = traceback.format_exc(limit=4)
            sys.stderr.write(f"[judge] decide() crashed:\n{detail}\n")
            self._send(200, {"decision": "ask",
                             "reason": "1. [注意] 判定器执行异常：本次检查过程中发生未捕获的异常，"
                                       "结论不可信，请人工确认这次调用。"})
            return
        if self.log_verbose:
            summary = ", ".join(f"{f.get('rule')}:{f.get('level')}" for f in result.findings) or "-"
            sys.stderr.write(f"[judge] {result.decision} ({summary})\n")
        if self.log_requests:
            # 旁路：写失败只往 stderr 说一句，不影响这次判定。
            _write_log(document, result, self.auto_approve)
        self._send(200, result.to_dict())


def _loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


#: `--logging` 的落盘目录：**项目自身文件夹**下的 `log/`，不是当前工作目录。
#: 用 `Path(__file__).parent` 就是为了这个——从别的目录启动也能写回项目里。
LOG_DIR = Path(__file__).resolve().parent / "log"

#: CLI 参数名 -> 等级的中文说明（**不含括号**：它会出现在 `--help` 的
#: `自动批准到 {…}` 里，也会出现在启动横幅的 `{参数名} ({…})` 里，自带括号会套成两层）。
LEVEL_LABEL_FOR_CLI = {
    "always-ask": "NEVER，永不自动放行",
    "skip-safe": "NONE，零发现才放行（默认）",
    "auto-approve": "LOW，[提示] 及以下",
    "report-warning": "MEDIUM，[注意] 及以下",
    "approve-all": "HIGH，[警告] 及以下",
}

#: 启动横幅里更短的写法，避免把参数名和等级名连读成一串。
LEVEL_DISPLAY = {
    "always-ask": "always-ask (NEVER)",
    "skip-safe": "skip-safe (NONE)",
    "auto-approve": "auto-approve (LOW)",
    "report-warning": "report-warning (MEDIUM)",
    "approve-all": "approve-all (HIGH)",
}


def _level_name(level: int) -> str:
    """等级上限 -> 可读名字，用于启动横幅。"""
    for name, value in AUTO_APPROVE_LEVELS.items():
        if value == level:
            return LEVEL_DISPLAY.get(name, name)
    return str(level)


def _level_name_long(level: int) -> str:
    """同上，但带上中文说明；用于日志（日志里空间不受限，说清更好）。"""
    for name, value in AUTO_APPROVE_LEVELS.items():
        if value == level:
            return f"{name} ({LEVEL_LABEL_FOR_CLI.get(name, '')})"
    return str(level)


def _write_log(document: dict[str, Any], result: Decision, level: int) -> None:
    """把一次请求写成一份日志。

    记**三样**：请求内容本身、判定的文字内容、决策结果。**approve 也记**——"放行了什么"和
    "拦下了什么"一样是审计对象，只记后者会让人以为没发生过。

    一天一个文件（`log/YYYY-MM-DD.log`），每条记录是 `--- 时间戳` 开头的一段，段落之间空行分隔。
    写失败不能影响判定：这里吞掉异常并往 stderr 说一句，因为日志是旁路，不是判定的一部分。
    """
    stamp = datetime.datetime.now()
    block = [
        f"--- {stamp.isoformat(timespec='seconds')}  decision={result.decision}  "
        f"auto-approve={_level_name_long(level)}",
        "请求:",
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True),
        "判定:",
        result.reason or "(无文字)",
        "",
        "",
    ]
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        path = LOG_DIR / f"{stamp:%Y-%m-%d}.log"
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(block))
    except OSError as error:
        sys.stderr.write(f"[judge] 写日志失败: {error}\n")


def build_server(host: str, port: int, token: str, verbose: bool,
                 auto_approve: int = 0, log_requests: bool = False) -> ThreadingHTTPServer:
    handler = type(
        "BoundJudgeHandler",
        (JudgeHandler,),
        {"token": token, "log_verbose": verbose, "auto_approve": auto_approve,
         "log_requests": log_requests},
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="DSH command-inspector judge server",
        epilog=(
            "自动批准等级（可重复，后面的覆盖前面的，默认 --skip-safe）：\n"
            "  --always-ask        永不自动放行，每条都问（含零发现）\n"
            "  --skip-safe         只自动放行零发现的调用（默认）\n"
            "  --auto-approve      最严重发现为 [提示] 及以下时自动放行\n"
            "  --report-warning    最严重发现为 [注意] 及以下时自动放行\n"
            "  --approve-all       最严重发现为 [警告] 及以下时自动放行\n"
            "  [拦截] (BLOCK) 不在任何等级之内：它是判定器唯一的 deny，任何参数都不会放行它。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default=os.environ.get("DSH_INSPECTOR_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DSH_INSPECTOR_PORT", "8791")))
    parser.add_argument("--token", default=os.environ.get("DSH_INSPECTOR_TOKEN", ""))
    parser.add_argument(
        "--analyzer",
        default=os.environ.get("COMMAND_INSPECTOR_SRC", ""),
        help="path to a command_inspector checkout (its src/ is added to sys.path; "
             "equivalent to setting COMMAND_INSPECTOR_SRC)",
    )
    parser.add_argument("--print-token", action="store_true", help="generate and print a token, then exit")
    parser.add_argument("--verbose", action="store_true", help="log every decision to stderr")
    parser.add_argument(
        "--logging",
        action="store_true",
        help="把每次请求的请求内容、判定文字与决策结果写入 ./log/（含 approve 的调用）",
    )
    # 五个自动批准等级：**同一个 dest**，所以重复出现时 argparse 自然取最后一个（后者覆盖前者）。
    # 默认取 --skip-safe，即"只有零发现的调用才自动放行"。
    parser.set_defaults(auto_approve=AUTO_APPROVE_LEVELS["skip-safe"])
    for _name, _level in AUTO_APPROVE_LEVELS.items():
        parser.add_argument(
            f"--{_name}",
            dest="auto_approve",
            action="store_const",
            const=_level,
            help=f"自动批准到 {LEVEL_LABEL_FOR_CLI.get(_name, _name)}",
        )
    parser.add_argument("--llama-url", default=os.environ.get(ENV_URL, ""), help="local model chat endpoint")
    parser.add_argument("--llama-model", default=os.environ.get(ENV_MODEL, ""), help="model id; read from /v1/models when omitted")
    parser.add_argument("--llama-timeout", default=os.environ.get(ENV_TIMEOUT, ""), help="seconds, default 25")
    parser.add_argument("--llama-policy", default=os.environ.get(ENV_POLICY, ""), help="off | on (default on)")
    args = parser.parse_args(argv)

    if args.print_token:
        print(secrets.token_urlsafe(32))
        return 0

    if not _loopback(args.host) and not args.token:
        sys.stderr.write("refusing to bind a non-loopback address without --token\n")
        return 2

    # Point at the analyzer before anything asks it a question. `capabilities()` below is the
    # first such call, and it is also what refuses to start when the analyzer is missing.
    if args.analyzer:
        analyzer_link.configure(args.analyzer)

    # The command line is the environment for the rest of the process: the local-model module
    # reads these names, so setting them here keeps one source of truth for configuration.
    if args.llama_url:
        os.environ[ENV_URL] = args.llama_url
    if args.llama_model:
        os.environ[ENV_MODEL] = args.llama_model
    if args.llama_timeout:
        os.environ[ENV_TIMEOUT] = args.llama_timeout
    if args.llama_policy:
        os.environ[ENV_POLICY] = args.llama_policy

    caps = capabilities()
    if not caps.get("available"):
        sys.stderr.write(f"analyzer unavailable: {caps.get('error')}\n")
        return 2

    server = build_server(args.host, args.port, args.token, args.verbose,
                          args.auto_approve, args.logging)
    where = f"http://{args.host}:{args.port}"
    print(f"judge listening on {where}")
    print(f"  behaviour  : {DECISION_BEHAVIOUR}")
    print(f"  analyzer   : {len(rule_names())} rules, frontends {caps.get('frontends')}")
    print(f"  judge rules: {len(known_rules())}")
    print(f"  auto-approve: {_level_name(args.auto_approve)}")
    print(f"  logging    : {'on -> ' + str(LOG_DIR) if args.logging else 'off'}")
    print(f"  local model: {'on -> ' + (args.llama_url or os.environ.get(ENV_URL, '')) if model_enabled() else 'off'}")
    print(f"  token      : {'required' if args.token else 'not required (loopback only)'}")
    print(f"  health: GET {where}/healthz   judge: POST {where}/dsh-judge")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
