"""Which DSH tool is which, and what the policy does with it.

The plugin sends the tool NAME as known fact. Nothing here infers a platform or a dialect from
text: `pwsh` is PowerShell, `bash` is bash, and that is the whole mapping. Tool names not listed
fall to the default, which asks — an unrecognised name is where a wrong guess would be silent.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Shell tools and the dialect the analyzer must be told. The name IS the answer.
SHELL_TOOLS: dict[str, str] = {
    "pwsh": "powershell",
    "powershell": "powershell",
    "cmd": "cmd",
    "bash": "bash",
    "sh": "bash",
    "shell": "bash",
    "terminal": "bash",
}

#: Tools that are approved outright: they report, queue, plan or message, and cannot change
#: anything on disk or in a running process. No content is inspected, by instruction.
ALWAYS_APPROVE: frozenset[str] = frozenset(
    {
        "ask_user_question",
        "create_goal",
        "exit_plan_mode",
        "get_goal",
        "job_list",
        "job_output",
        "list_agents",
        "present",
        "todo_write",
        "todo_get",
        "todo_list",
        "todo_update",
        "update_goal",
        "send_message",
        # 定时提醒：和 goal 一样是纯状态管理（增删改查自己的提醒表），不读写文件。
        # 四种操作都只动这一层状态，所以整体放行。
        "schedule_create",
        "schedule_delete",
        "schedule_update",
        "schedule_list",
    }
)

#: 参数里看不出行为的工具：它们会把内容送进模型上下文、派生出别的 agent，或者对另一个 agent
#: 的工作动手。**等级是 `MEDIUM`**，不是"无脑拒绝"。
#:
#: 按上游对四个等级的定义：
#:
#: * `LOW`     不一定危险，但用户值得知道的信息；
#: * `MEDIUM`  关键操作，不一定危险，但需要用户知情并确认的操作；
#: * `HIGH`    在正常做项目或写代码的流程中几乎不可能用到的操作；
#: * `BLOCK`   明确的危险操作。
#:
#: 这些工具全是 `MEDIUM`：它们是正常流程里会用到、也不一定有害的动作，只是参数看不出它要做什么。
#: `interrupt_agent` 尤其如此——agent 只有 AI 自己才能创建，所以被中断的必然是它自己派生的东西，
#: 属于"值得让用户知道，这会丢失中间状态"，而不是"编程中几乎不可能出现的操作"。这和
#: `delete-outside-workspace` 判 `MEDIUM` 是同一个理由。
#:
#: **文案只写"这个工具在做什么"，一句话，不加解释。** 凡是**不随参数变化**的后果说明都是废信息：
#: "对方的中间状态会丢失"每次都是这句，读者读完不会得到任何判断依据，只是多读一行。真正随参数
#: 变化的发现（比如 `web_fetch` 的替代端点）才值得写出来。
CONFIRM_TOOLS: dict[str, str] = {
    "interrupt_agent": "中断另一个 agent",
    "job_kill": "终止一个后台任务",
    "skill": "加载技能说明",
    "subagent": "派生子 agent",
    "subagent_fork": "从当前会话派生 agent",
    "workflow": "运行多 agent 编排脚本",
    "ralph": "循环执行直到成功",
}

#: 搜索类：查询词会发到外部服务，内容本身没有可审查的部分，也没有明确的"更好端点"可言。
#: 按等级定义属于 `LOW`——不一定危险，但用户值得知道。同样只写一句话。
SEARCH_TOOLS: dict[str, str] = {
    "web_search": "发起联网搜索",
}

#: Tools that read or search. Reach is reported, content is not interpreted.
READ_TOOLS: frozenset[str] = frozenset({"read", "read_image", "glob", "grep"})

#: Tools that write a file's contents. Checked for content AND for local facts about the target.
WRITE_TOOLS: frozenset[str] = frozenset({"write", "edit"})

#: 改会话工作目录的工具。参数是 `{cd?: string}`：**省略 `cd` 就只是读**当前目录，不动任何状态，
#: 那种情况直接放行；给了 `cd` 才需要判断新目录是否还在工作区内。
CWD_TOOLS: frozenset[str] = frozenset({"working_directory"})


@dataclass(frozen=True)
class ToolPolicy:
    """How one tool is judged. `family` selects the code path; the rest is descriptive."""

    family: str
    note: str = ""


def policy_for(tool: str) -> ToolPolicy:
    name = tool.lower()
    if name in SHELL_TOOLS:
        return ToolPolicy("shell", f"以 {SHELL_TOOLS[name]} 语义解析命令")
    if name in ALWAYS_APPROVE:
        return ToolPolicy("approve", "不改变任何状态，直接放行")
    if name in CONFIRM_TOOLS:
        return ToolPolicy("confirm", CONFIRM_TOOLS[name])
    if name in SEARCH_TOOLS:
        return ToolPolicy("search", SEARCH_TOOLS[name])
    if name in READ_TOOLS:
        return ToolPolicy("read", "只读访问，检查触及范围")
    if name in WRITE_TOOLS:
        return ToolPolicy("write", "写入文件，检查内容与目标")
    if name in CWD_TOOLS:
        return ToolPolicy("cwd", "更改会话工作目录，检查是否跳出工作区")
    if name == "web_fetch":
        return ToolPolicy("fetch", "抓取网页内容，内容会进入模型上下文")
    return ToolPolicy("unknown", "未知工具，无法判断其行为")


def shell_dialect(tool: str) -> str | None:
    return SHELL_TOOLS.get(tool.lower())
