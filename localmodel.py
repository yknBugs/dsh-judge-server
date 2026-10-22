"""Optional advisory pass from a local model.

This affects the DISPLAY only. The decision is computed before anything here runs; a note can be
appended to the reason text and nothing else. It cannot turn an ask into a deny, cannot turn a
deny into an ask, and cannot approve. Every failure — endpoint down, too slow, answers with HTML,
answers with something unparseable — returns nothing at all, so the feature can be enabled without
weakening the guarantee that a judge failure never fails open.

Why a local model at all: it can phrase what it notices in a way a fixed rule table cannot, and it
costs no API credit. Why it stays advisory: a small model asked "is this dangerous" produces
confident text either way, so its output is a hint for the human reader, never a verdict.

Configuration::

    DSH_INSPECTOR_LLAMA_URL       chat endpoint; a bare host:port is completed for you
    DSH_INSPECTOR_LLAMA_MODEL     model id; read from /v1/models when omitted
    DSH_INSPECTOR_LLAMA_TIMEOUT   seconds, default 25
    DSH_INSPECTOR_LLAMA_POLICY    off | on  (default on)

The model receives the tool call and NOTHING else — in particular not the analyzer's findings.
Feeding a small model the list of what was already noticed anchors it into restating that list,
which is the one thing this pass is supposed to add to. It also never receives file contents read
by the evidence layer: those are the bytes most likely to hold a credential or an injection
payload, and this request leaves the judge process.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

POLICY_OFF = "off"
POLICY_ON = "on"
POLICIES = (POLICY_OFF, POLICY_ON)

DEFAULT_TIMEOUT_SECONDS = 25.0
MAX_NOTE_CHARS = 700
MAX_TOKENS = 200
MAX_PROMPT_ARG_CHARS = 1500

#: The card is Chinese, so the note is asked for in Chinese. The model still reasons about the
#: call itself; only the language of its answer is prescribed.
_SYSTEM_PROMPT = (
    "你坐在一个即将批准或拒绝某次 AI 工具调用的人旁边。你只看到这次调用本身，没有别人"
    "看过它。\n"
    "你的任务：指出这次调用值得再看一眼的地方，或者使用者可能没注意到的地方。最多三行短句，"
    "用中文。\n"
    "不要开场白，不要编号，不要复述命令，不要 markdown 标题，不要说教，不要泛泛而谈备份或"
    "权限的重要性。\n"
    "如果这次调用没什么可说的，只回复：无异常\n"
    "你不做任何决定，你也不是审批者。"
)

ENV_URL = "DSH_INSPECTOR_LLAMA_URL"
ENV_MODEL = "DSH_INSPECTOR_LLAMA_MODEL"
ENV_TIMEOUT = "DSH_INSPECTOR_LLAMA_TIMEOUT"
ENV_POLICY = "DSH_INSPECTOR_LLAMA_POLICY"


def endpoint() -> str:
    """The configured value, verbatim."""
    return os.environ.get(ENV_URL, "").strip()


def chat_endpoint() -> str:
    """The URL to POST to, completing a bare host:port into the chat path.

    Accepts both spellings so the command line cannot be silently wrong::

        http://127.0.0.1:12345                      -> .../v1/chat/completions
        http://127.0.0.1:12345/v1/chat/completions  -> unchanged

    Without this, a bare host:port would POST to the server root, which llama.cpp answers with
    something that is not a completion, and the note would silently never appear.
    """
    url = endpoint()
    if not url:
        return ""
    if re.search(r"/v1/(chat/)?completions/?$", url):
        return url
    return url.rstrip("/") + "/v1/chat/completions"


def policy() -> str:
    """``off`` or ``on``. An unknown value means ``on``."""
    value = os.environ.get(ENV_POLICY, "").strip().lower()
    return POLICY_OFF if value == POLICY_OFF else POLICY_ON


def enabled() -> bool:
    return endpoint() != "" and policy() != POLICY_OFF


def timeout_seconds() -> float:
    try:
        value = float(os.environ.get(ENV_TIMEOUT, "").strip())
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return value if 1.0 <= value <= 300.0 else DEFAULT_TIMEOUT_SECONDS


def discover_model(base_url: str, timeout: float) -> str:
    """Read the model id from a llama.cpp ``/v1/models`` listing."""
    root = re.sub(r"/v1/(chat/completions|completions)/?$", "", base_url.rstrip("/")) or base_url
    try:
        with urllib.request.urlopen(f"{root}/v1/models", timeout=min(timeout, 5.0)) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return ""
    models = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(models, list) and models and isinstance(models[0], dict):
        return str(models[0].get("id") or "")
    return ""


def _condense(text: str, limit: int = MAX_PROMPT_ARG_CHARS) -> str:
    text = text.replace("\r\n", "\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _user_prompt(tool: str, args: dict[str, Any], cwd: str) -> str:
    lines = [f"工具: {tool}"]
    if cwd:
        lines.append(f"工作目录: {cwd}")
    lines.append("参数:")
    for name, value in args.items():
        rendered = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        lines.append(f"  {name} = {_condense(rendered)}")
    return "\n".join(lines)


def _post(url: str, payload: dict, timeout: float) -> dict | None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return None


def note_for(tool: str, args: dict[str, Any], cwd: str) -> str:
    """Ask the local model for an advisory note, or return ``''``.

    Returns ``''`` on every failure path, so a caller cannot mistake an unreachable model for an
    opinion.
    """
    url = chat_endpoint()
    if not url:
        return ""
    timeout = timeout_seconds()
    model = os.environ.get(ENV_MODEL, "").strip() or discover_model(url, timeout)
    if not model:
        return ""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _user_prompt(tool, args, cwd)},
        ],
        "max_tokens": MAX_TOKENS,
        "temperature": 0.0,
        "stream": False,
        # Qwen-family templates honour this and would otherwise spend the whole token budget on a
        # reasoning block; other templates ignore the extra key.
        "chat_template_kwargs": {"enable_thinking": False},
    }
    response = _post(url, payload, timeout)
    if not response:
        return ""
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return ""
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return ""
    content = str(message.get("content") or "").strip()
    if not content:
        return ""
    if content.lower().startswith(("nothing notable", "无异常")):
        return ""
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    return "\n".join(lines[:3])[:MAX_NOTE_CHARS]
