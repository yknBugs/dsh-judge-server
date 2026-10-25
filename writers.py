"""判定卡片上的中文文案。你要改文案，只改这个文件。

## 一条规则一个函数

每条规则是一个函数，拿一个 `Finding`，返回**卡片上那一行的全部内容**。函数体就是顺序拼接，所以"这条规则
有哪些参数可用"直接在它自己的函数体里看得见，不用去查占位符表：

    def w_delete_variable_unresolved(f: Finding) -> str:
        t = ""
        if f.force:
            t += "强制"
        if f.recursive:
            t += "递归"
        t += "删除目标含有变量"
        if f.variables:
            t += " (" + f.list(f.variables) + ") "
        ...
        return "删除目标含变量，无法界定" + '：' + t

**函数返回什么，卡片上就是什么**。判定器只在前面加 `序号. [等级] `，后面连 `标题：描述` 这种结构都由你决定——想只写一句话就只写一句话。

## 可用字段

`f.<字段名>` 直接取 `data` 里的键，字段不存在时是 `None`、空值是 `[]`/`()`，
所以 `if f.force:`、`if f.variables:` 都能直接写，不会 AttributeError。
字段名与中文标签的对照表见下面 `FACT_LABEL`。

除了原字段，`Finding` 还提供几个常用短语和一个条件判断：

| 用法 | 含义 |
| --- | --- |
| `f.target` | 单个目标路径；没有 `target` 字段时退回 `targets` |
| `f.list(f.variables)` | 列表拼成中文顿号串 |
| `f.operation_text` | 操作的中文动词 (`list` -> 列出目录)  |
| `f.reason_text` | 原因代码的中文；没登记的原样返回 |
| `f.tool_name` / `f.tool_category` | `tool-invoked` 的软件名与类别 |
| `f.sql_parts` | SQL 的对象、种类与方言 |
| `f.evidence_text` | 磁盘实测数据 (删几个文件、多大)  |
| `f.facts()` | 机器生成的事实行，例如 `操作: delete｜目标: /x｜递归: 是` |
| `f.scope_text` / `f.where_note` / `f.publish_note` / `f.package_note` | 几个常用短语 |
| `f.loop` / `f.branch` / `f.conditional` | 是否仅在循环体／某个分支里执行 |
| `f.conditions` | 条件句原文列表 |
| `f.condition_text()` | 条件的中文短语，例如 `循环体或所在分支` |

## 事实行

以前每条描述前面会自动拼一行机器生成的事实 (`操作: delete｜目标: …`) 。现在**不自动加**，
由文案自己决定：想带上就写 `t += f.facts()`，不想带就不写。

## 可用字段

`Finding` 提供两种取用方式，混着用没问题：

* 属性直取：`f.target`、`f.recursive`、`f.variables` —— 字段不存在时是 `None`，
  空值是 `[]` / `()`，所以 `if f.force:`、`if f.variables:` 都能直接写。
* `f.get("target")`、`f.has("force")`、`f.list(f.targets)`、`f.verbs("强制", "递归")`
  —— 需要更细的控制时用。

已知字段见下面 `FACT_LABEL`，那是"字段名 -> 中文标签"的表；要给新字段起中文名就改它。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from rules_zh import LEVEL_LABEL, JUDGE_ERROR_RULE, INFORMATIONAL, label_for

__all__ = [
    "Finding",
    "RULE_WRITERS",
    "render",
    "facts_line",
    "translate_guard",
    "FACT_LABEL",
]


# ─────────────────────────────────────────────────────────────────────────────
# 词表
# ─────────────────────────────────────────────────────────────────────────────

#: 分析器的操作名 -> 中文动词。`unresolved-value`、`unsupported-syntax` 这些规则会因为好几种
#: 不同操作而触发，只看规则名分不出来；有了动词，卡片才能说清"列出目录"还是"读取文件"。
OPERATION_VERB = {
    "list": "列出目录",
    "ingest": "读取文件",
    "overwrite": "写入文件",
    "append": "追加写入",
    "move": "移动文件",
    "copy": "复制文件",
    "delete": "删除",
    "create": "创建",
    "inspect": "检查内容",
    "request": "发起网络请求",
    "download": "下载",
    "upload": "上传",
    "publish": "发布",
    "read": "读取",
    "write": "写入",
    "parse": "解析命令",
    "unsupported-syntax": "分析语法",
    "encoded-command": "解码并执行",
    "privilege-escalation": "提权执行",
    "environment-modified": "修改环境变量",
    "errors-suppressed": "抑制错误输出",
    "readonly-assignment-failed": "对只读变量赋值",
    "account-change": "修改账户",
    "backup-delete": "删除备份",
    "event-log-clear": "清空日志",
    "free-space-wipe": "擦除空闲空间",
    "machine-power-change": "关机或重启",
    "registry-change": "修改注册表",
    "runtime-code-loading": "动态加载代码",
    "security-policy-change": "修改安全策略",
    "service-change": "修改服务",
    "volume-format": "格式化卷",
    "docker-change": "修改容器资源",
    "filesystem-selection-delete": "删除筛选结果",
    "sql-row-change": "修改数据行",
    "sql-schema-change": "修改表结构",
    "sql-truncate": "截断表",
    "sql-remove-schema": "删除结构对象",
    "sql-privilege-change": "修改数据库权限",
    "sql-create-identity": "创建数据库身份",
    "sql-drop-object": "删除数据库对象",
    "sql-unresolved": "解析 SQL ",
    "unknown-command": "执行命令",
    # 1.6.0 路径调用，以及其它新暴露出来的操作名。缺一个，卡片上就会出现
    # "将由 artifact 执行的代码内容" 这种半英文句子。
    "execute": "执行",
    "artifact": "运行文件",
    "path_invocation": "按路径调用",
    "create_directory": "创建目录",
    "filtered_delete": "删除筛选结果",
    "unknown_pipe_effect": "管道传递",
    "analyze": "解析",
    "invoke": "调用",
    "transform": "转换",
    "transfer": "传输",
    "assignment": "赋值",
    "unresolved": "解析未完成",
}

#: 分析器的原因代码 -> 中文。两族代码都进这里：证据层的 (`*_budget`/`*_failed`) ，以及
#: `Value.reason` (说明某个操作数为什么绑定不上) 。取自分析器源码，因为目录里的
#: `data_schema` 目前还是空占位，没有列举它们。
REASON_TEXT = {
    # —— 命令与语法层
    "behavior_not_modeled": "命令的行为未知",
    "missing_parser": "缺少对应的解析器",
    "unsupported_dialect": "语法格式未知",
    "unsupported_statement": "语句类型未知",
    "unsupported_module_entrypoint": "模块入口未知",
    "parse_failed": "解析失败",
    "tokenization_failed": "处理语义单元失败",
    "syntax_budget": "使用的语法过于复杂",
    "unsupported_expression": "表达式作用未知",
    "unsupported_selection_parameters": "筛选参数作用未知",
    "runtime_or_unsupported_expansion": "展开方式未知",
    "unsupported_parameter_expansion": "参数的展开方式未知",
    "unsupported_argument_binding": "无法确定参数与取值的对应关系",
    "unsupported_word": "包含无法识别的文字",
    # —— 只有运行时才有值的操作数
    "missing_variable": "引用了未定义的变量",
    "loop_variable": "循环变量在循环外没有值",
    "loop_variable_unresolved": "无法确定循环变量的取值",
    "runtime_input": "变量的值来自运行时输入",
    "dynamic_expression": "变量的值依赖于动态表达式的结果",
    "dynamic_mapping": "变量的值依赖于动态映射的结果",
    "array_argument": "变量的值依赖于数组参数",
    "array_binding": "数组元素与参数无法对应",
    "range_expression": "变量的值是区间表达式",
    "compound_assignment": "变量的值来自复合赋值",
    "conditional_assignment": "变量的值取决于条件赋值是否生效",
    "conditional_binding": "变量的值取决于特定条件是否生效",
    "conditional_readonly": "变量的值取决于读取结果",
    "unquoted_split_or_glob": "缺少引号导致存在被分词或展开通配符的可能",
    "delayed_expansion_unsupported": "延迟展开的行为未知",
    "unresolved_delayed_expansion": "无法确定延迟展开后的取值",
    "missing_or_batch_variable": "无法确定批处理变量取值",
    "unresolved_assignment": "赋值表达式的取值未知",
    "unresolved_composition": "多段取值拼成的结果未知",
    # —— 1.12/1.13 的运行时与信任边界
    "formatted_timestamp": "取值来自格式化时间戳",
    "hex_digest": "取值来自摘要输出",
    "numeric_runtime": "取值来自数字计数或运算",
    "trusted_script_state": "可信脚本执行后的状态未知",
    "unresolved_append_target": "追加写入的目标未知",
    "transfer_selection_unavailable": "传输的文件筛选结果未知",
    # —— 文件、传输与数据流
    "missing_source": "缺少来源",
    "missing_destination": "缺少目标",
    "missing_operand": "缺少操作数",
    "missing_output_destination": "缺少输出目标",
    "conflicting_destination_forms": "目标写法互相冲突",
    "unresolved_source": "无法确定来源",
    "unresolved_item_name": "无法确定条目名",
    "find_result": "取值取决于查找的结果",
    "formatted_files": "取值来自格式化输出",
    "generated_files": "取值来自生成的文件",
    "sourced_state": "取值依赖输入的内容",
    "unknown_option_binding": "无法确定选项与取值的对应关系",
    "unknown_option_operand_binding": "选项改变了操作数的对应关系",
    "unknown_parameter_binding": "无法确定参数与取值的对应关系",
    "wildcard_creation_not_modeled": "通配符会创建新文件",
    "wrapped_source_budget": "数据来源过于复杂",
    # —— 证据层
    "evidence_disabled": "未能从磁盘上收集证据",
    "changed_earlier": "目标已在本次命令中被修改",
    "may_have_changed_earlier": "目标可能已在本次命令中被修改",
    "nonlocal_or_unresolved_path": "路径无法解析",
    "host_path_style_mismatch": "路径风格与本机不一致",
    "filesystem_access_failed": "访问文件系统失败",
    "not_regular_file": "目标不是文件",
    "directory_link_not_followed": "目标不跟随目录链接",
    "recursive_selection_unavailable": "递归筛选的结果未知",
    "powershell_recursive_pattern_semantics_unavailable": "PowerShell 递归通配符的行为未知",
    "unresolved_pattern_base": "无法确定通配符的起始目录",
    "locale_pattern_not_modeled": "本地化通配符的行为未知",
    "globstar_not_modeled": "通配符的行为未知",
    "entry_limit": "条目过于复杂",
    "total_entry_budget": "条目数量过多",
    "total_read_budget": "读取总量过大",
    "long_encoded_blob": "编码的数据块过长",
    "routine_body_uninspected": "检查例行程序体失败",
    "missing": "目标不存在",
    "encoded command argument": "参数是编码后的命令",
    "self-evaluating command": "参数会自求值",
    "decoded payload piped to a shell": "命令先经过解码后再交给终端执行",
}

#: 分析器把"这个效果只在某条件下发生"作为条件句接在 `detail` 后面。那是真信息：循环体里
#: 无法解析的取值，只有循环真的跑了才成立，漏掉它会让卡片把话说得比事实更满。
#: 集合很小且封闭；没登记的原样显示，因为读者看不懂的条件句也比看不见的条件句强。
#: 值是短语形式，拼进句子用；`Finding.condition_text()` 会自动取用。
#: 分析器给的条件从句 -> 中文短语。
#:
#: 这份清单是**从真实产出里穷举出来的** (`tools/inventory_guards_actual.py` 拿分析器测试语料当
#: 命令池，跑 8571 次分析收集所有 `detail` 里的条件) ，不是靠读源码猜——静态扫源码会把 docstring、
#: 配置键、字段名一起扫进来，实测 39 个"缺翻译"里只有 9 个是真的。
#:
#: 漏一条的后果是卡片上直接出现英文 (`且仅在during expression evaluation成立`) ，所以新增规则或
#: 升级分析器后要重跑那个工具。
GUARD_TEXT = {
    "if the loop body runs": "循环体执行时",
    "if this body runs": "所在分支执行时",
    "if the preceding command succeeds": "前一条命令成功时",
    "if the preceding command fails": "前一条命令失败时",
    "during command substitution": "命令替换中",
    "if a search result matches": "有搜索结果匹配时",
    # 1.9.0 实测补的 9 条。
    "during expression evaluation": "表达式求值时",
    "if the CMD loop body runs": "cmd 循环体执行时",
    "if the CMD condition holds": "cmd 条件成立时",
    "if the user switch succeeds": "切换用户成功时",
    "if the loop condition is evaluated": "循环条件被求值时",
    "if earlier conditions are false": "前面的条件都不成立时",
    "if the binding is readonly on this path": "该变量在此路径上是只读时",
    "if the ForEach-Object begin block runs": "ForEach-Object 的 begin 块执行时",
    "if the ForEach-Object end block runs": "ForEach-Object 的 end 块执行时",
    # 1.10.0 新增：`try`/`catch`/`finally` 的块体、bash 的 while 条件、pwsh 的 `&&`/`||` 链。
    # 前三条来自 `pwsh/semantics.py` 的 try_flow (474/489/496) ，第 4 条来自 `bash/semantics.py`
    # 的 while_loop (631) ，最后一条来自 `pwsh/semantics.py` 的 pipeline_chain (378) 。
    "if the try body runs": "try 块体执行时",
    "if this catch body runs": "catch 块体执行时",
    "when the finally body runs": "finally 块体执行时",
    "when evaluating the loop condition": "计算循环条件时",
    "conditional on the preceding command": "前一条命令的结果满足条件时",
}

#: 分析器拼在 `detail` 尾部、但**不是条件句**的能力标记。目前只有一个：
#: `detectors.py` 的 `emit` 在"这条结论建立在多个可能值之上"时追加的
#: `one of the bounded possible command meanings`。它的事实已经由 `data.possible` /
#: `data.possible_values` 承载，卡片上有中文说法；当条件渲染会漏出英文。
CAPABILITY_MARKERS = frozenset({"one of the bounded possible command meanings"})

#: SQL 规则报告的对象种类，让"删除整个对象"能说清是表、列还是用户。
OBJECT_KIND_TEXT = {
    "table": "表",
    "view": "视图",
    "schema": "模式",
    "column": "列",
    "index": "索引",
    "database": "数据库",
    "user": "用户",
    "login": "登录名",
    "role": "角色",
    "privilege": "权限",
    "statement": "语句",
    "function": "函数",
    "sequence": "序列",
    "trigger": "触发器",
    "type": "类型",
}

#: `tool-invoked` 的领域类别。这些是分析器给的英文短语，直接拼进中文句子会变成半句英文。
#: 未登记的类别原样显示——半句英文也比"类别: 未知"更有信息。
TOOL_CATEGORY_TEXT = {
    "package manager": "包管理器",
    "firewall controller": "防火墙控制器",
    "network and firewall configuration": "网络与防火墙配置",
    "network interface": "网络接口",
    "network interface and routing": "网络接口与路由",
    "network manager": "网络管理器",
    "routing table": "路由表",
    "wireless interface": "无线接口",
    "traffic control": "流量控制",
    "kernel parameters": "内核参数",
    "kernel module": "内核模块",
    "account management": "账户管理",
    "group management": "用户组管理",
    "credential management": "口令管理",
    "privilege configuration": "权限配置",
    "privilege change": "权限变更",
    "access control": "访问控制",
    "ownership change": "属主变更",
    "identity service": "身份服务",
    "authentication configuration": "认证配置",
    "key material": "密钥材料",
    "key and certificate material": "密钥与证书材料",
    "certificate material": "证书材料",
    "scheduled tasks": "计划任务",
    "service management": "服务管理",
    "process manager": "进程管理",
    "log access": "日志访问",
    "filesystem creation": "文件系统创建",
    "filesystem mounting": "文件系统挂载",
    "filesystem unmounting": "文件系统卸载",
    "filesystem repair": "文件系统修复",
    "filesystem maintenance": "文件系统维护",
    "filesystem management": "文件系统管理",
    "filesystem search with actions": "带动作的文件搜索",
    "partition table": "分区表",
    "volume management": "卷管理",
    "swap control": "交换区控制",
    "swap creation": "交换区创建",
    "RAID configuration": "RAID 配置",
    "irreversible deletion": "不可恢复的删除",
    "in-place file truncation": "原地截断文件",
    "space allocation": "空间分配",
    "file attributes": "文件属性",
    "archive extraction": "解包",
    "synchronisation, including deletions": "同步 (含删除)",
    "remote shell": "远程 shell",
    "remote transfer": "远程传输",
    "remote execution": "远程执行",
    "raw network endpoint": "裸网络端点",
    "packet capture": "抓包",
    "network transfer": "网络传输",
    "signal delivery": "发送信号",
    "process priority": "进程优先级",
    "resource limits": "资源限制",
    "machine power state": "整机电源状态",
    "boot configuration": "启动配置",
    "firmware": "固件",
    "hardware inventory": "硬件清单",
    "disk health": "磁盘健康",
    "container runtime": "容器运行时",
    "orchestration": "编排",
    "virtual machine": "虚拟机",
    "cloud control plane": "云控制面",
    "infrastructure as code": "基础设施即代码",
    "configuration management": "配置管理",
    "version control": "版本控制",
    "event log": "事件日志",
    "audit configuration": "审计配置",
    "audit records": "审计记录",
    "log rotation": "日志轮转",
    "logging service": "日志服务",
    "database dump": "数据库导出",
    "database restore": "数据库恢复",
    "database file": "数据库文件",
    "database client": "数据库客户端",
    "data store": "数据存储",
    "time-series store": "时序存储",
    "shell history": "shell 历史",
    "command pipelining": "命令管道",
    "dynamic evaluation": "动态求值",
    "environment manipulation": "环境操作",
    "option manipulation": "选项操作",
    "shell indirection": "shell 间接调用",
    "shell inclusion": "shell 引入",
}

#: `action` 字段是英文动词 (`stop`、`sc create`、`volume rm`、`--unset`…) 。文案要说的是中文，
#: 所以在这里翻好，写文案时直接 `f"{f.action}了…"` 就是通顺的句子，不必再套一个 ` (stop) `。
#:
#: 复合动作 (`sc create`、`docker volume rm`) 按最长后缀匹配：`sc create` 命中 `create`，
#: 前缀 `sc` 由 `ACTION_PREFIX_TEXT` 决定怎么呈现。
ACTION_TEXT = {
    "start": "启动",
    "stop": "停止",
    "restart": "重启",
    "reload": "重载",
    "enable": "启用",
    "disable": "停用",
    "delete": "删除",
    "uninstall": "卸载",
    "install": "安装",
    "create": "创建",
    "config": "配置",
    "modify": "修改",
    "set": "修改",
    "add": "新增",
    "remove": "移除",
    "rm": "删除",
    # 动词只管动作，别把对象塞进来：`rmi` 说"删除"，"镜像"由 `docker rmi` 的 `docker` 前缀补。
    # 这样同一条动作嵌进别的语境 (比如服务) 也不会出现"删除镜像系统服务"。
    "rmi": "删除",
    "kill": "强制停止",
    "prune": "清理",
    "down": "停止并移除",
    "unset": "取消设置",
    "update": "修改",
    "insert": "插入",
    "truncate": "清空",
    "drop": "删除",
    "grant": "授予",
    "revoke": "收回",
    "pause": "暂停",
    "unpause": "恢复",
    "purge": "彻底清除",
    "reset": "重置",
    "push": "推送",
    "pull": "拉取",
    "tag": "打标签",
    "exec": "在容器内执行",
    # 只读动作：正常不该走到"修改了 X"的句子里，但真出现了也得是中文，
    # 不能让 `get了` 这种半英文半中文的写法出现在卡片上。
    "get": "读取",
    "list": "列出",
    "show": "显示",
    "query": "查询",
    "status": "查看状态",
    "check": "检查",
    # 实测补的 (`tools/inventory_actions_actual.py` 从 8598 次分析里穷举出来的，
    # 这些是 `translate_action` 原来认不出、会把英文漏到卡片上的) 。
    "login": "登录",
    "run": "运行",
    "build": "构建",
    "reload": "重载",
    "register": "注册",
    "unregister": "注销",
    "end": "结束",
    "new": "新建",
}

#: 连字符/斜杠动作里的**对象**，用来把 `stop-scheduledtask` 说成"停止计划任务"而不是
#: "停止scheduledtask"。只收实测出现过的；认不出就只出动词，不硬拼英文。
ACTION_OBJECT_TEXT = {
    "service": "服务",
    "scheduledtask": "计划任务",
    "scheduled": "计划",
    "task": "任务",
    "process": "进程",
    "item": "项",
    "content": "内容",
    "job": "任务",
    "daemon": "守护进程",
    "container": "容器",
    "image": "镜像",
    "volume": "数据卷",
    "network": "网络",
    "user": "账户",
    "group": "用户组",
}

#: 复合动作前缀的呈现方式。前缀只在**它真的补充信息**时才该出现：
#:
#: * `sc create` 的 `sc` —— 说明这是服务控制器，但 `service-change` 那句本身已经在说"系统服务或者
#:   计划任务"，再加"系统服务"就重复成"系统服务创建系统服务或者计划任务"。所以这里留空，只用动词。
#: * `volume rm` 的 `volume` —— 在 `docker-change` 里必须留，否则"删除容器资源"说不清删的是卷。
ACTION_PREFIX_TEXT = {
    "sc": "",
    "volume": "数据卷",
    "system": "系统",
    "compose": "编排",
    "image": "镜像",
    "container": "容器",
    "network": "网络",
}

#: `scope` 字段。
SCOPE_TEXT = {"global": "全局", "local": "本地", "system": "系统"}

#: 路径调用规则 (1.6.0) 的字段。
#: `path_type` 说的是"这个路径是怎么写的"：绝对写法还是相对写法。这不是废话——相对路径的落点
#: 取决于当前目录，换个目录就是另一个文件。
PATH_TYPE_TEXT = {"absolute": "绝对路径", "relative": "相对路径"}

#: "有没有核对过这个路径"。`available` 表示分析器真的看了磁盘，此时"目标不存在"之类的结论是
#: 实测；`unavailable` 表示没看，结论只是词法推断。**卡片必须说出来**，否则会把"我没查"
#: 读成"我查过且没问题"。
EVIDENCE_STATUS_TEXT = {
    "available": "已核对磁盘",
    "unavailable": "未核对磁盘",
    "missing": "磁盘上不存在",
}

#: 候选值被放弃、退回"无法确定"的原因 (1.9.0 的 `data.unresolved_reasons`) 。
#: 这三个都是**有界的**：不是分析器不会算，而是到了配置的上限就停手，宁可说"不确定"也不给一个
#: 看着安全的子集。
UNRESOLVED_REASON_TEXT = {
    "possible_values_limit": "变量可能的值太多",
    "control_flow_limit": "逻辑复杂度太高",
    "value_bytes_limit": "单个变量值太大",
}

#: 证据强度不足导致"查不了"的原因 (`data.reason` = `effort_partial` / `effort_none`) 。
#:
#: 这两个**必须翻译并出现在卡片上**。同样是"读不到内容"，一档是"我查了元数据但按约定不读内容"，
#: 另一档是"我完全没碰磁盘"——读者要据此判断该不该自己去核一眼。少了这半句，两张卡片长得
#: 一模一样，而它们的确信度差一档。
EFFORT_REASON_TEXT = {
    "effort_partial": "文件内容未知",
    "effort_none": "目标文件状态未知",
}

#: 其它会让"内容查不了"的原因。
OTHER_INCOMPLETE_REASON_TEXT = {
    "unsupported_or_incomplete_source": "包含无法理解的语法结构",
    "possible_python_mutation": "代码本身可能会对目标文件进行修改",
}

#: 路径是按什么算出来的 (`data.path_basis`) 。`lexical` 很重要：那是**纯字面拼接**，没有查过
#: 磁盘，也没有解析符号链接。
PATH_BASIS_TEXT = {
    "lexical": "按字面拼接",
    "observed": "按磁盘实际",
    "evidence": "按文件内容",
    "constrained_runtime": "按运行时值约束到目录",
}


def translate_action(code: str) -> str:
    """英文动作 -> 中文动词。

    分析器发的 `action` 有四种形状，都要认：

    * 单个动词 —— `stop`；
    * 空格分隔的复合 —— `sc create`、`container start`；
    * **连字符分隔的 verb-noun** —— `new-service`、`stop-scheduledtask` (PowerShell 风格) ；
    * **斜杠分隔** —— `schtasks /create`、`schtasks /delete`。

    两种拼法不同，不能混为一谈：

    * **动词在最后** (`sc create`、`schtasks /create`) ：前面那截是**调用者/程序名**，
      照原样保留并在中间留一个空格 —— `schtasks 创建`，不是 `schtasks创建`；
    * **动词在最前** (`new-service`、`stop-scheduledtask`) ：后面那截是**操作对象**，
      翻成中文接在动词后 —— `新建服务`、`停止计划任务`。

    认不出来就**原样返回** (不猜) 。那种情况卡片上会露出英文，所以新增规则或升级分析器后要重跑
    `tools/inventory_actions_actual.py`。
    """
    text = (code or "").strip()
    if not text:
        return ""
    cleaned = text.lstrip("-")
    if cleaned in ACTION_TEXT:
        return ACTION_TEXT[cleaned]

    # 斜杠和连字符都当分隔符：`schtasks /create` -> [`schtasks`, `create`]，
    # `stop-scheduledtask` -> [`stop`, `scheduledtask`]。
    words = cleaned.replace(":", " ").replace("/", " ").replace("-", " ").split()
    if not words:
        return text

    # 情形一：动词在最后 (最长后缀优先，`docker compose config` 这类多词前缀也能覆盖) 。
    for split in range(len(words) - 1, 0, -1):
        verb = " ".join(words[split:])
        if verb in ACTION_TEXT:
            prefix = " ".join(words[:split])
            head = ACTION_PREFIX_TEXT.get(prefix)
            if head is None:
                # 未登记的前缀 (程序名、`buildx` 之类) 原样保留，**中间留空格**，
                # 否则会和中文粘成 `schtasks创建`。
                head = f"{prefix} " if prefix else ""
            return f"{head}{ACTION_TEXT[verb]}"

    # 情形二：动词在最前，后面是操作对象 (`new-service`、`stop-scheduledtask`) 。
    if words[0] in ACTION_TEXT:
        target = _action_object(" ".join(words[1:])) if len(words) > 1 else ""
        rest = " ".join(words[1:])
        if target:
            return f"{ACTION_TEXT[words[0]]}{target}"
        # 对象认不出：若后面那截本身是个已知动词就当它 (`daemon-reload` 的 `reload`) ，
        # 否则只出动词，不把英文拼进中文句子。
        if len(words) > 1 and words[-1] in ACTION_TEXT:
            return f"{rest} {ACTION_TEXT[words[-1]]}" if len(words) > 2 else ACTION_TEXT[words[-1]]
        return ACTION_TEXT[words[0]]
    return text


def _action_object(rest: str) -> str:
    """动作对象的中文；认不出返回空串 (宁可只出动词，也不把英文拼进中文句子) 。"""
    if not rest:
        return ""
    if rest in ACTION_OBJECT_TEXT:
        return ACTION_OBJECT_TEXT[rest]
    parts = rest.split()
    # 逐词拼合：`scheduled task` -> `scheduledtask`；也试单独的最后一段 (`scheduledtask` 那种
    # 没分隔符的写法要靠对象表里有完整词) 。
    joined = "".join(parts)
    if joined in ACTION_OBJECT_TEXT:
        return ACTION_OBJECT_TEXT[joined]
    for word in reversed(parts):
        if word in ACTION_OBJECT_TEXT:
            return ACTION_OBJECT_TEXT[word]
    return ""


def translate_scope(code: str) -> str:
    """`scope` 可能是 `global`，也可能是 `scope:system` 这种带前缀的形式。"""
    text = (code or "").strip()
    if not text:
        return ""
    cleaned = text.split(":")[-1].strip() if ":" in text else text
    return SCOPE_TEXT.get(cleaned, cleaned)


#: 事实字段的中文标签。新字段出现在卡片上时用的是英文原键名，往这里加一行就变成中文。
FACT_LABEL = {
    "operation": "操作",
    "action": "动作",
    "target": "目标",
    "targets": "目标",
    "destinations": "地址",
    "objects": "对象",
    "object_kind": "类型",
    "dialect": "方言",
    "interpreters": "解释器",
    "variables": "变量",
    "keys": "配置项",
    "refspecs": "引用",
    "options": "选项",
    "principals": "被授权者",
    "privileges": "权限",
    "scope": "作用域",
    "mode": "权限位",
    "statement_index": "语句序号",
    "recursive": "递归",
    "force": "强制",
    "has_where": "带 WHERE 条件",
    "single_target": "单一目标",
    "targets_resolved": "目标已解析",
    "destination_resolved": "地址已解析",
    "selection_resolved": "选择已枚举",
    "search_roots": "搜索根",
    "path_basis": "路径依据",
    "reason": "原因",
    "tool": "软件",
    "category": "类别",
    "behavior_modeled": "行为已建模",
    "importance": "重要度",
    "history_scope": "历史范围",
    "command": "命令",
    "command_resolved": "命令名已确定",
    "patterns": "通配符",
    "source": "来源",
    "context": "上下文",
    "tool_category": "类别",
    "written_file": "写入文件",
    "existing_bytes": "原有字节",
    "written_bytes": "写入字节",
    "before_bytes": "修改前字节",
    "after_bytes": "修改后字节",
    "delta_bytes": "字节变化",
    "occurrences": "出现次数",
    "lines": "行数",
    "cwd": "工作目录",
}

#: 这些键的值就是整句话本身，摊成事实只会重复。
FACT_SKIP = frozenset({"source", "context", "type", "title", "detail"})

#: 哪些字段里装的是"被调用的软件名"。
TOOL_NAME_FIELDS = ("tool", "command")
#: 类别字段用过两种拼法，都认。
TOOL_CATEGORY_FIELDS = ("category", "tool_category")


# ─────────────────────────────────────────────────────────────────────────────
# 文案拿到的那个对象
# ─────────────────────────────────────────────────────────────────────────────

def _join(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return "、".join(str(item) for item in value if item not in (None, ""))
    return "" if value is None else str(value)


def _first(data: dict, *keys: str) -> str:
    for key in keys:
        text = _join(data.get(key))
        if text:
            return text
    return ""


#: 中日韩字符与"需要留白"的字符。
_CJK = "\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff"
_LATIN = "A-Za-z0-9"

#: 中文与拉丁字之间的边界 (两侧各一个捕获组，便于回调里保留原字符) 。
_CJK_LATIN_BOUNDARY = re.compile(
    rf"(?<=[{_CJK}])(?=[{_LATIN}])|(?<=[{_LATIN}])(?=[{_CJK}])"
)


def space_cjk_latin(text: str) -> str:
    """在中文和拉丁字之间补一个空格：`或try 块体` -> `或 try 块体`。

    这份文案一贯这样写 (`使用 node 执行代码`、`包含未知命令 test`、`删除 /work/a 中的内容`) ，
    因为中文夹拉丁词时不留白，读者会把两边的边界看错。

    **不碰已经有空格的地方**，也不碰标点旁边 (`/etc，` 这种靠调用方自己决定空格) 。
    """
    if not text:
        return text
    return _CJK_LATIN_BOUNDARY.sub(" ", text)


@dataclass(frozen=True)
class Finding:
    """一条待渲染的发现，给文案用。

    字段用 `data` 里的原键名直取 (`f.target`、`f.recursive`、`f.variables`…) ，取不到时是
    `None`，所以 `if f.force:` 这种写法永远安全，不会 AttributeError。
    """

    rule: str
    level: str
    data: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[dict, ...] = ()
    title: str = ""
    detail: str = ""

    # —— 原始取值 ——
    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def has(self, key: str) -> bool:
        value = self.data.get(key)
        return value not in (None, "", [], {}, ())

    #: 这些字段在上游是列表，拼进句子前必须转成文字。
    #: 写成 `t += f.variables` 会漏出 `['T']` 这种 Python 语法——机器写的列表表示不是中文。
    LIST_FIELDS = frozenset(
        {
            "targets", "destinations", "objects", "interpreters", "variables", "keys", "refspecs",
            "options", "principals", "privileges", "search_roots", "patterns", "affected_paths",
        }
    )

    def __getattr__(self, key: str) -> Any:
        # data 里的键可以直接当属性用；不存在的键给 None，让 if 判断不必先做 has()。
        if key.startswith("_"):
            raise AttributeError(key)
        data = self.__dict__.get("data") or {}
        if key == "target":
            # `target` 与 `targets` 在上游是两个不同的键：单个路径，和路径列表。各条规则用哪个
            # 并不一致，所以 `f.target` 两个都认。
            #
            # 无论来自哪个键，**返回的都必须是能直接拼进句子的文字**：拼 `f.target` 时不能
            # 冒出 `['nginx']` 这种 Python 列表写法。所以走 `targets` 时用中文顿号拼好。
            single = data.get("target")
            if single not in (None, "", [], {}, ()):
                return single
            many = data.get("targets")
            if many in (None, "", [], {}, ()):
                return None
            return _join(many)
        value = data.get(key)
        if key in self.LIST_FIELDS and isinstance(value, (list, tuple)):
            # 列表一律在这里就拼成文字。写文案的人不必记得哪个字段是列表——忘了就会印出
            # `['T']`，而那是机器语法，不是给用户看的句子。
            return _join(value)
        if key == "action":
            # 直接给中文动词：写 `f"{f.action}了…"` 就是句子，不必再套一个 ` (stop) `。
            return translate_action(str(value)) if value else None
        if key == "scope":
            return translate_scope(str(value)) if value else None
        return value

    # —— 常用整形 ——
    @staticmethod
    def list(value: Any) -> str:
        """列表拼成中文顿号串。"""
        return _join(value)

    @property
    def operation_text(self) -> str:
        """操作的中文动词，例如 `list` -> 列出目录。"""
        return OPERATION_VERB.get(_join(self.data.get("operation")), "")

    @property
    def reason_text(self) -> str:
        """原因代码的中文；没登记的原样返回，不吞掉。"""
        return translate_reason(_join(self.data.get("reason")))

    @property
    def reason_code(self) -> str:
        """原因代码本身。

        `data.reason` 是正式位置；但上游有几处把原因代码直接当**标题**用 (`cat "$FILE"` 的标题
        就是 `missing_variable`) ，那种情况下 `data.reason` 是空的。这里把两处都认了，写文案时
        只判断 `f.reason_code` 就够，不必知道它藏在哪。
        """
        code = _join(self.data.get("reason"))
        if code:
            return code
        if self.title in REASON_TEXT:
            return self.title
        return ""

    @property
    def incomplete_because(self) -> str:
        """"查不了"的原因，成句、可用作附注；说不清就返回空串。

        优先说证据档位 (`effort_partial` / `effort_none`) ，因为那是**读者的可行动信息**：
        他知道自己是主动关掉了磁盘查询，还是按约定只查了元数据。其余原因再退回通用表。
        """
        code = self.reason_code
        if not code:
            # `evidence_status` 单独出现时也能说明一点：至少说清"没核对磁盘"。
            if _join(self.data.get("evidence_status")) == "unavailable":
                return EFFORT_REASON_TEXT["effort_none"]
            return ""
        text = EFFORT_REASON_TEXT.get(code) or OTHER_INCOMPLETE_REASON_TEXT.get(code)
        if text:
            return text
        translated = REASON_TEXT.get(code)
        return translated or ""

    # —— 变量"所有可能的值" (1.9.0) ——
    @property
    def is_possible(self) -> bool:
        """这条结论是在"有限多个可能值"上得出的，不是唯一确定的那一种。

        分析器不再"分支不同就当无法确定"，而是保留有界的候选值 (`possible: true`) ，逐个候选
        做检查。卡片上要把这件事说出来 —— 否则读者会以为只发生了一次、且就是那一个目标。
        """
        return bool(self.data.get("possible"))

    @property
    def possible_values(self) -> list[tuple[str, list[str]]]:
        """`{变量名: [候选值…]}`，保持分析器给的顺序 (去重后的插入序) 。

        敏感变量的候选值上游已经替换成 `["[REDACTED]"]`，这里原样透传，不再加工。
        """
        raw = self.data.get("possible_values")
        if not isinstance(raw, dict):
            return []
        pairs: list[tuple[str, list[str]]] = []
        for name, values in raw.items():
            if isinstance(values, (list, tuple)):
                pairs.append((str(name), [str(value) for value in values]))
            else:
                pairs.append((str(name), [str(values)]))
        return pairs

    @property
    def possible_annotation(self) -> str:
        """**内联注解**，紧跟在变量名后面：`(可能为 a.txt 或 b.txt)`。

        这是候选值的**唯一**呈现方式。要写成"变量的注解"而不是"另起一句"：

            对：删除目标依赖于变量 A (可能为 b.txt 或 a.txt) 且可能删除 /work/a.txt
            错：删除 /work/a.txt。可能的值：A 可能为 b.txt 或 a.txt。

        错的那种前面一句完全不提 A，后面突然塞进 A 的取值，读者莫名其妙。

        多个变量时按 `possible_values` 的顺序各给一个注解，调用方用 `、` 连接：

            删除目标依赖于变量 A (可能为 b.txt 或 a.txt)、D (可能为 other 或 sub) 且…

        圆括号用**半角**：注解紧跟在变量名 (拉丁字母) 后面，半角括号和拉丁标识符是一体的；
        括号内是中文取值时仍读得通。
        """
        pairs = self.possible_values
        if not pairs:
            return ""
        rendered = []
        for name, values in pairs:
            joined = " 或 ".join(values)
            rendered.append(f"{name} (可能为 {joined})" if name else joined)
        return "、".join(rendered)

    @property
    def possible_names(self) -> str:
        """只列变量名：`A、D`。用于"依赖于变量 …"这半句。"""
        pairs = self.possible_values
        return "、".join(name for name, _values in pairs if name)

    @property
    def possible_note(self) -> str:
        """**已废弃**：把候选值另起一句的写法。

        保留它只为不打断既有调用方；新文案一律用 `possible_annotation` (内联注解) 。
        按用户的要求，候选值必须作为**变量名的注解**出现，不能另起一句——否则前一句不提变量，
        后一句突然出现它的取值，读起来莫名其妙。

        没有候选明细时返回空串 (不再输出"取值未知"那种多余的话) 。
        """
        annotation = self.possible_annotation
        return f"可能的值：{annotation}。" if annotation else ""

    #: 兼容旧名。
    @property
    def possible_text(self) -> str:
        return self.possible_annotation

    @property
    def unresolved_reasons(self) -> str:
        """为什么候选值被放弃、退回"无法确定"。

        上游给三种：候选值太多、控制流步数超限、单个值太大。说出来读者才知道边界在哪。
        """
        raw = self.data.get("unresolved_reasons")
        if not isinstance(raw, (list, tuple)) or not raw:
            return ""
        translated = [UNRESOLVED_REASON_TEXT.get(str(code), str(code)) for code in raw]
        return "、".join(dict.fromkeys(translated))

    @property
    def path_basis_text(self) -> str:
        """路径是按什么算出来的。`lexical` 是"按字面拼出来的"，**没看过磁盘**。"""
        code = _join(self.data.get("path_basis"))
        return PATH_BASIS_TEXT.get(code, code)

    @property
    def tool_name(self) -> str:
        return _first(self.data, *TOOL_NAME_FIELDS)

    @property
    def tool_category(self) -> str:
        return _first(self.data, *TOOL_CATEGORY_FIELDS)

    @property
    def tool_category_text(self) -> str:
        """类别的中文；没登记的原样返回，不吞掉。"""
        return TOOL_CATEGORY_TEXT.get(self.tool_category, self.tool_category)

    @property
    def sql_parts(self) -> str:
        """SQL 的对象与种类，例如 `users (表) `。

        方言不放在这里：它更适合作为"这是什么数据库"出现一次，而不是每句话尾巴都拖一个
        `postgres 方言`。要单独用它就取 `f.dialect`。多个对象之间用顿号连。

        括号用**全角**、**不带尾随空格**：这段文字会被嵌进 `"…{action}了 {subject}，…"` 这种
        模板，半角括号加尾随空格会让标点前多一个空格 (`users (表)  。`) 。
        """
        objects = _join(self.data.get("objects"))
        kind = OBJECT_KIND_TEXT.get(_join(self.data.get("object_kind")), _join(self.data.get("object_kind")))
        if objects and kind:
            return f"{objects}（{kind}）"
        return objects or kind

    # —— 条件 ——
    @property
    def conditions(self) -> tuple[str, ...]:
        """分析器给出的条件句，已拆成一条条原文。"""
        return split_guard(self.detail, self.title)

    @property
    def loop(self) -> bool:
        return "if the loop body runs" in self.conditions

    @property
    def branch(self) -> bool:
        return "if this body runs" in self.conditions

    @property
    def conditional(self) -> bool:
        """是否只在某种条件下成立 (循环或分支) 。"""
        return self.loop or self.branch

    def condition_text(self, joiner: str = "或") -> str:
        """条件的中文短语，比如 `循环体或所在分支`；没有条件时返回空串。

        拼接处要补空格：有些译文以拉丁字开头 (`cmd 循环体执行时`、`ForEach-Object 的 begin 块执行时`、
        `try 块体执行时`) ，直接接在 `或` 后面会挤成 `或try 块体执行时`。中文和拉丁字之间留一个空格
        是这份文案一贯的写法 (`使用 node 执行代码`、`包含未知命令 test`) 。
        """
        parts = [GUARD_TEXT[item] for item in self.conditions if item in GUARD_TEXT]
        parts += [item for item in self.conditions if item not in GUARD_TEXT]
        joined = joiner.join(dict.fromkeys(parts))
        return space_cjk_latin(joined)

    # —— 事实行与动词 ——
    def facts(self) -> str:
        """机器生成的事实行，例如 `操作: delete｜目标: /x｜递归: 是`。"""
        return facts_line(self.data)

    def verbs(self, *labels: str) -> str:
        """给定标签里"成立"的那些接起来，方便拼前缀。"""
        return "".join(labels)

    @property
    def evidence_text(self) -> str:
        return _render_evidence(self.evidence)

    @property
    def target_missing(self) -> bool:
        """这条发现的目标是否**确认不存在**。

        分析器把"查过、确实没有"记成 `evidence` 里 `status == "missing"`。注意这**不是**
        "查不了"：查不了的是 `unavailable`，那种情况不能说"不存在"。

        删除类规则用它把两句话合成一句：`删除工作目录内的文件 X，X 不存在。` 里那个路径写了两遍，
        改成 `要删除的工作目录内的文件 X 不存在。`
        """
        for record in self.evidence:
            if isinstance(record, dict) and record.get("status") == "missing":
                return True
        return False

    # —— 几个常用短语，省得每条规则各写一遍 ——
    @property
    def scope_text(self) -> str:
        """`global 作用域的 `；没有作用域时是空串。"""
        scope = _join(self.data.get("scope"))
        return f"{scope} 作用域的 " if scope else ""

    @property
    def where_note(self) -> str:
        """SQL 的过滤条件说明。`None` 表示分析器没能确定。"""
        where = self.data.get("has_where")
        if where is True:
            return "，带 WHERE 条件"
        if where is False:
            return "，没有 WHERE 条件，会影响整表"
        return "，过滤条件无法确定"

    @property
    def publish_note(self) -> str:
        """远端地址没解析出来时补一句；能确定就什么都不加。"""
        return "，但远端地址无法确定" if self.data.get("destination_resolved") is False else ""

    @property
    def package_note(self) -> str:
        """包名列表；分析器常常给不出，那就如实说没指明。"""
        names = _join(self.data.get("targets"))
        return names if names else ""


def translate_reason(code: str) -> str:
    return REASON_TEXT.get(code.strip(), code.strip())


def translate_guard(text: str) -> str:
    """条件句的中文片段；没登记的原样返回。"""
    return GUARD_TEXT.get(text.strip(), text.strip())


def split_guard(detail: str, title: str) -> tuple[str, ...]:
    """把 `detail` 尾部的条件句拆出来。

    分析器把条件接在标题后面 (`title + "; " + guard`) ，条件之间再用 `; ` 相连。所以拆解规则很
    简单，但必须按整句相等来判：`detail` 里别处的分号不该被当成条件。

    **要滤掉分析器的能力标记。** 除了条件，分析器还会往 `detail` 尾巴上追加一句
    `one of the bounded possible command meanings` (见 `detectors.py` 的 `emit`) 来表示"这条结论
    建立在多个可能值之上"。它是能力标记，不是条件从句，但当条件渲染就会漏出一句英文：

        …且仅在one of the bounded possible command meanings成立，无法确定…

    它想表达的事实已经由 `data.possible` / `data.possible_values` 承载，卡片上有对应的中文说法，
    所以这里直接丢掉，不当作条件。
    """
    if not detail or detail == title or not detail.startswith(title):
        return ()
    tail = detail[len(title):].lstrip("; ").strip()
    if not tail:
        return ()
    parts = (part.strip() for part in tail.split(";"))
    return tuple(part for part in parts if part and part not in CAPABILITY_MARKERS)


def facts_line(data: dict[str, Any]) -> str:
    """把 `data` 摊开成一行 `标签: 值`。

    刻意不依赖文案：文案是逐条手写的，会滞后于新字段，而这里渲染的是分析器实际放进 `data`
    的东西。所以一条还没翻译的规则，卡片上照样能说清操作和目标。
    """
    parts: list[str] = []
    for key, value in data.items():
        if key in FACT_SKIP or value in (None, "", [], {}, ()):
            continue
        label = FACT_LABEL.get(key, key)
        if isinstance(value, bool):
            parts.append(f"{label}: {'是' if value else '否'}")
            continue
        if key == "reason":
            # 原因是机器标识符，正文里已经有中文说法，留着代码会让同一行出现两种语言。
            parts.append(f"{label}: {translate_reason(_join(value))}")
            continue
        rendered = _join(value) if isinstance(value, (list, tuple)) else str(value)
        if rendered:
            parts.append(f"{label}: {rendered}")
    return "｜".join(parts)


def _render_evidence(evidence: tuple[dict, ...]) -> str:
    """磁盘实测数据，压成一句。"""
    parts: list[str] = []
    for record in evidence:
        status = record.get("status")
        if status == "missing":
            parts.append(f"{record.get('source', '目标')} 不存在")
        elif "files" in record:
            files = record.get("files", 0)
            directories = record.get("directories", 0)
            bytes_ = record.get("logical_bytes", 0)
            prefix = "将" if record.get("affected_paths_complete", True) else "可能至少"
            parts.append(f"{prefix}删除 {files} 个文件、{directories} 个目录，共约 {bytes_} 字节")
    return ": ".join(dict.fromkeys(parts))


# ─────────────────────────────────────────────────────────────────────────────
# 各规则的文案：一条规则一个函数
# ─────────────────────────────────────────────────────────────────────────────
#
# 每个函数拿一个 `Finding`，返回**卡片上那一行的全部内容** (判定器只加 `序号. [等级] `) 。
# 函数体就是顺序拼接，所以"这条规则有哪些参数可用"直接在它自己的函数体里看得见。
#
# 句子尽量写成 f-string (`t += f" {f.target} "`) ，别拆成好几条 `t += str(...)`。
# 想知道所有可用字段、以及字段缺失时会退化成什么，看上面 `Finding` 的属性和 `finding-fields` 注释。
#
def w_read_outside_workspace(f: Finding) -> str:
    """read-outside-workspace

    **候选值是变量名的内联注解，不是另起一句。** 用户的目标句式：

        读取的目标文件依赖于变量 F (可能为 /etc/hostname 或 a.txt) 且可能是在工作目录外的 /etc/hostname

    反过来 (`读取工作目录外的 /etc/hostname。可能的值：F 可能为 …。`) 前面不提 F，后面突然塞进
    F 的取值，读者莫名其妙。所以有候选时把"依赖于变量 …"这半句放在前面，注解紧跟变量名。

    没有候选值时保持原来的短句 (`读取工作目录外的 /x。`) ，不硬套那个句式。
    """
    name = f.target or ""
    scope = f.get("scope_root")
    pattern = f.get("pattern")
    annotation = f.possible_annotation
    target = f" {name} " if name else ""
    tail = f" {name}" if name else ""
    if annotation:
        # 把"取决于哪个变量"说在前面，目标跟在后面。注解后**不加逗号**：`…a.txt) 且可能…`
        # 直接连读比 `…a.txt)，且可能…` 顺。
        where = f"且可能是在工作目录外的{tail}" if not f.cwd else (
            f"且可能不在当前工作区 {f.cwd} 内")
        return f"读取的目标文件依赖于变量 {annotation} {where}。"
    if f.cwd:
        return f"读取的文件{target}不在当前工作区 {f.cwd} 内。"
    if f.tool:
        return f"{f.tool} 需要读取文件{target}。"
    if pattern:
        return f"读取工作目录外的 {pattern}。"
    if scope:
        return f"读取工作目录外 {scope} 下的文件。"
    if tail:
        return f"读取工作目录外的{tail}。"
    return "读取工作目录外的文件。"


def w_cwd_outside_workspace(f: Finding) -> str:
    """cwd-outside-workspace (`working_directory` 的 `cd` 跳出工作区) 

    **只陈述发现：新工作目录在哪儿、和当前工作区的关系。** 不说"后续相对路径都会在那个目录下
    解析"——那是推论，读者自己会想到；也不说"建议不要切到外面"——那是在教怎么绕过。

    路径已经把 `..` 折叠过了 (`filechecks.resolve_path`) ，所以显示的是**落点**，不是用户写的
    那串字符；两者不同时 (`../../etc` 与 `/etc`) 要一并给出，否则读者会以为自己写的没问题。
    """
    target = f.target or ""
    requested = f.get("requested")
    where = f"工作目录外的 {target}" if target else "工作目录外的目录"
    if isinstance(requested, str) and requested and requested != target:
        return f"把会话工作目录切到{where}（写的是 {requested}）。"
    return f"把会话工作目录切到{where}。"


def w_write_outside_workspace(f: Finding) -> str:
    """write-outside-workspace

    `check == "write"` 是写入，`"edit"` 是修改；shell 那条没有 `check`，说的是"写入目标"。
    同 `w_read_outside_workspace`：句尾用 `tail`，避免句号前多一个空格。
    """
    name = f.target or ""
    scope = f.get("scope_root")
    target = f" {name} " if name else ""
    tail = f" {name}" if name else ""
    cwd = f.cwd
    if str(f.get("check")) == "edit":
        if cwd:
            return f"修改的文件{target}不在当前工作区 {cwd} 内。"
        if scope:
            return f"修改工作目录外 {scope} 下的文件。"
        return f"修改工作目录外的文件{tail}。"
    if cwd:
        return f"写入的文件{target}不在当前工作区 {cwd} 内。"
    if scope:
        return f"写入工作目录外 {scope} 下的文件。"
    return f"写入工作目录外的文件{tail}。"


def w_delete_inside_workspace(f: Finding) -> str:
    """delete-inside-workspace

    1.9.0 起，分支/循环里的变量不再直接变成"无法确定"，而是保留**有界的候选值**，逐个候选各出
    一条 finding (所以可能同时出现"删 a.txt"和"删 b.txt"两条) 。

    **候选值是变量名的内联注解。** 用户的目标句式：

        删除目标依赖于变量 A (可能为 b.txt 或 a.txt)、D (可能为 other 或 sub) 且可能删除工作目录内的文件 /work/sub/b.txt

    有候选时把"依赖于变量 …"放在前面、目标跟在后面；没有候选时保持短句。

    **目标确认不存在时不再复述路径。** `删除工作目录内的文件 X，X 不存在。` 一行里那个路径写了
    两遍，读着费劲；改成 `要删除的工作目录内的文件 X 不存在。`
    """
    name = f.target or ""
    scope = f.get("scope_root")
    annotation = f.possible_annotation
    tail = f" {name}" if name else "文件"
    if f.target_missing and not annotation:
        return f"要删除的工作目录内的文件{tail}不存在。"
    if annotation:
        return f"删除目标依赖于变量 {annotation} 且可能删除工作目录内的文件{tail}。"
    t = "删除工作目录内的"
    if f.target:
        t += f"文件 {f.target}"
    elif scope:
        t += f" {scope} 下的文件"
    else:
        t += "文件"
    if f.evidence_text:
        t += "，" + f.evidence_text
    return t + "。"


def w_delete_outside_workspace(f: Finding) -> str:
    """delete-outside-workspace

    同 `w_delete_inside_workspace`：候选值作为变量名的内联注解，不另起一句；目标确认不存在时
    写成 `要删除的工作目录外的文件 X 不存在。`
    """
    name = f.target or ""
    scope = f.get("scope_root")
    annotation = f.possible_annotation
    tail = f" {name}" if name else "文件"
    if f.target_missing and not annotation:
        return f"要删除的工作目录外的文件{tail}不存在。"
    if annotation:
        return f"删除目标依赖于变量 {annotation} 且可能删除工作目录外的文件{tail}。"
    t = "删除工作目录外的"
    if f.target:
        t += f" {f.target}"
    elif scope:
        t += f" {scope} 下的文件"
    else:
        t += "文件"
    if f.evidence_text:
        t += "，" + f.evidence_text
    return t + "。"


def w_delete_workspace_root(f: Finding) -> str:
    """delete-workspace-root"""
    if f.get("possible"):
        where = f" {f.target}" if f.target else "某个位置"
        t = f"删除目标可能是{where}，包含当前工作目录本身"
    else:
        t = "删除目标"
        if f.target:
            t += f" {f.target} "
        t += "包含当前工作目录本身"
    if f.evidence_text:
        t += f"，{f.evidence_text}"
    else:
        t += "。"
    return t


def w_delete_protected_root(f: Finding) -> str:
    """delete-protected-root"""
    if f.get("possible"):
        where = f" {f.target}" if f.target else "某个位置"
        t = f"删除目标可能是{where}，包含关键系统目录"
    else:
        t = "删除目标"
        if f.target:
            t += f" {f.target} "
        t += "包含关键系统目录"
    if f.evidence_text:
        t += f"，{f.evidence_text}"
    else:
        t += "。"
    return t


def w_delete_after_failed_assignment(f: Finding) -> str:
    """delete-after-failed-assignment"""
    t = "在变量赋值失败后仍使用其旧值进行删除操作"
    if f.evidence_text:
        t += f"，{f.evidence_text}"
    else:
        t += "。"
    return t


def w_delete_target_missing(f: Finding) -> str:
    """delete-target-missing"""
    if f.target:
        return f"要删除的目标 {f.target} 不存在。"
    return "要删除的目标不存在。"


def _variable_reference(f: Finding) -> str:
    """**变量的统一说法**：`变量 n (可能为 a 或 b)` / `变量 m、n (可能为 a 或 b)`。

    候选值是变量名的内联注解，不是另起一句。所有"句子提到某个变量"的 writer 都用它，
    免得每处各写一遍、各漏一遍。

    两种来源可能**指不同的变量**，必须分开列：

    * `data.variables` —— 值根本没解析出来的变量 (`m`) ；
    * `data.possible_values` —— 有界候选的变量 (`n`) 。

    所以 `variables=['m']` + `possible_values={'n': ['a','b']}` 要写成：

        变量 m、n (可能为 a 或 b)

    也就是 `variables` 里**没出现在候选里**的名字先列出来、用顿号连，候选注解跟在最后。

    命名上：`possible_annotation` 只产出 `n (可能为 a 或 b)`，不带"变量"二字；句子需要一个
    名词短语 (`…取决于变量 … 的值`) ，所以这里补上"变量"。
    """
    annotation = f.possible_annotation
    names = f.list(f.variables)
    if annotation and names:
        # 候选注解里已经带了某个变量名，`variables` 里其余名字要单独列在前面。
        covered = set(f.possible_values and [name for name, _v in f.possible_values] or [])
        # `variables` 是顿号串，重新按列表取，才能剔除被候选覆盖的名字。
        raw = f.data.get("variables")
        listed = [str(item) for item in raw] if isinstance(raw, (list, tuple)) else [names]
        extra = [item for item in listed if item not in covered]
        if extra:
            return f"变量 {'、'.join(extra)}、{annotation}"
        return f"变量 {names}"
    if annotation:
        return f"变量 {annotation}"
    if names:
        return f"变量 {names}"
    # 连变量名都没有就别写"变量"——`取决于变量 的值` 是个病句。
    return "运行时的值"


def w_delete_variable_unresolved(f: Finding) -> str:
    """delete-variable-unresolved

    提到变量就把候选做成变量名的内联注解 (`_variable_reference`) 。这条**确实**会遇到两者
    都有的情况：cmd 的 `for %n in (a b) do rd /s /q %n` 带
    `variables=['n']` + `possible_values={'n': ['a','b']}`。
    """
    t = ""
    if f.force:
        t += "强制"
    if f.recursive:
        t += "递归"
    t += "删除的目标含有"
    t += _variable_reference(f)
    t += "，"
    if f.loop or f.branch:
        t += "且仅在"
        where = []
        if f.loop:
            where.append("循环体")
        if f.branch:
            where.append("所在分支")
        t += "或".join(where) + "执行时成立，因此"
    else:
        t += "因此"
    t += "无法确定将被删除的目标。"
    return t


def w_delete_recursion_unresolved(f: Finding) -> str:
    """delete-recursion-unresolved

    提到变量就把候选做成变量名的内联注解。

    `_variable_reference` 的产出可能以变量名或 `)` 结尾 (拉丁字符) ，所以后面接"的值"时要留一个
    空格，否则会粘成 `变量 t的值`。没有变量名时它返回"运行时的值"，那时就不再补"的值"了
     (否则成了 `运行时的值 的值`) 。
    """
    reference = _variable_reference(f)
    if reference == "运行时的值":
        return f"递归删除的目标取决于运行时的值，因此无法确定将被删除的目标。"
    return f"递归删除的目标取决于{reference} 的值，因此无法确定将被删除的目标。"


def w_write_variable_unresolved(f: Finding) -> str:
    """write-variable-unresolved

    提到变量就把候选做成变量名的内联注解。同 `w_delete_recursion_unresolved`。
    """
    reference = _variable_reference(f)
    if reference == "运行时的值":
        return f"写入的目标取决于运行时的值，因此无法确定将被写入的目标。"
    return f"写入的目标取决于{reference} 的值，因此无法确定将被写入的目标。"


def w_overwrite_existing_file(f: Finding) -> str:
    """overwrite-existing-file"""
    if f.target:
        if f.get("possible"):
            return f"可能会覆盖 {f.target} 中的内容。"
        return f"本次操作会覆盖 {f.target} 中的内容。"
    return "本次操作可能覆盖已经存在的文件。"


def w_permissions_too_broad(f: Finding) -> str:
    """permissions-too-broad"""
    t = "将"
    if f.target:
        t += f" {f.target} 的"
    t += "权限设"
    if f.mode:
        t += f"成过大的 {f.mode}"
    else:
        t += "的过大"
    t += "。"
    return t


def w_filesystem_selection_delete(f: Finding) -> str:
    """filesystem-selection-delete

    用"是"而不是"来自于从"——后者两个介词叠在一起，读着像病句。
    """
    if f.search_roots:
        return f"删除的目标是从 {f.list(f.search_roots)} 中筛选的结果，因此无法确定具体目标。"
    return "删除的目标是筛选结果，因此无法确定将要删除的文件。"


def w_written_source_syntax_error(f: Finding) -> str:
    """written-source-syntax-error"""
    return "写入的内容可能包含语法错误。"


def w_credentials_read(f: Finding) -> str:
    """credentials-read

    说出是哪个文件：`read`/`grep` 那条带 `target`，比笼统一句"将要读取的内容可能包含凭据"
    更能让人判断该不该放行。shell 那条 (`cat ~/.ssh/id_rsa`) 没有 target，只能笼统说。
    """
    if f.target:
        return f"将要读取的 {f.target} 可能包含凭据。"
    return "将要读取的内容可能包含凭据。"


def w_credentials_written(f: Finding) -> str:
    """credentials-written"""
    if f.target:
        return f"写入 {f.target} 的内容里疑似包含凭据。"
    return "写入的内容里疑似包含凭据。"


def w_hardcoded_secret(f: Finding) -> str:
    """hardcoded-secret (1.10.0 新增) 

    分析器原话：`Source contains a hard-coded credential.` `data` 给两样具体信息：
    `variables` (硬编码进了哪个变量) 和 `line` (在第几行) 。

    **知道什么就写什么**：位置和变量名都是随参数变化的，写出来读者才能直接跳过去改；凭据值本身
    不写 (分析器也不给，它只给 redact 之后的值) 。
    """
    names = f.list(f.get("variables"))
    line = f.get("line")
    has_line = isinstance(line, int) and line > 0
    if names and has_line:
        return f"{names} 的值被硬编码在源码第 {line} 行。"
    if names:
        return f"{names} 的值被硬编码在源码里。"
    if has_line:
        return f"源码第 {line} 行硬编码了凭据。"
    return "源码里硬编码了凭据。"


#: `credentials-exposed` 的 `data.channel`：密码是**怎么**进去的。
#:
#: 通道不同，暴露面不同：经标准输入只留在这次调用的输入里，作为命令行参数则会进命令历史、
#: 进程列表和审计日志。所以要说清是哪一种，不能笼统一句"密码暴露了"。
EXPOSURE_CHANNEL_TEXT = {
    "stdin": "标准输入",
    "argv": "命令行参数",
    "environment": "环境变量",
    "file": "文件",
}


def w_credentials_exposed(f: Finding) -> str:
    """credentials-exposed (1.10.0 新增) 

    分析器原话：`Visible command input supplies a password to an authentication consumer.`
    `data` 给两个字段：`consumer` (谁在要密码，实测只有 `sudo`) 和 `channel` (怎么进去的，
    实测只有 `stdin`) 。

    **只陈述发现：明文密码经某个通道交给了某个要认证的程序。** 不说"建议改用…"——那是在教
    怎么绕过这次检查；也不说"密码会留在历史里"——那是读者已经知道的常识。

    两个字段都可能缺 (新版本加了别的消费者/通道) ，所以逐级退化而不是硬拼。
    """
    consumer = str(f.get("consumer") or "").strip()
    channel = EXPOSURE_CHANNEL_TEXT.get(str(f.get("channel") or "").strip().casefold(), "")
    if channel and consumer:
        return f"密码以明文经{channel}交给了 {consumer}。"
    if channel:
        return f"密码以明文经{channel}交给了需要认证的程序。"
    if consumer:
        return f"密码以明文交给了 {consumer}。"
    if f.variables:
        return f"输出了包含凭据的变量 {f.variables}。"
    return "命令里以明文给出了密码。"


def w_prompt_injection_read(f: Finding) -> str:
    """prompt-injection-read"""
    return "读到的内容里可能包含针对模型的指令。"


def w_ingestion_inspection_incomplete(f: Finding) -> str:
    """ingestion-inspection-incomplete

    **只陈述发现：读取的内容没有被完整检查。**

    不补"由于当前证据强度只查元数据…"这类档位理由。理由不是发现；用户要的是"命令里值得关注的点"，
    而"这次读取的内容没被完整检查过"本身就已经是那个点。

    **候选值是变量名的内联注解。** 用户的目标句式：

        将要读取的内容依赖于变量 F (可能为 /etc/hostname 或 a.txt) 且无法对其进行完整检查。

    有候选时"依赖于变量 …"放在前面，读者的顺序才是"为什么不确定 → 所以查不完整"。
    """
    annotation = f.possible_annotation
    if annotation:
        return f"将要读取的内容依赖于变量 {annotation} 且无法对其进行完整检查。"
    return "无法对将要读取的内容进行完整检查。"


def w_unreadable_payload(f: Finding) -> str:
    """unreadable-payload"""
    return "无法对所有参数进行校验。"


def w_obfuscated_payload(f: Finding) -> str:
    """obfuscated-payload"""
    if f.reason_text:
        return f"由于{f.reason_text}，无法确定命令的具体效果。"
    return "由于参数是编码或自求值的形式，无法判断具体效果。"


def w_uses_interpreter(f: Finding) -> str:
    """uses-interpreter"""
    if f.interpreters:
        return f"使用 {f.list(f.interpreters)} 执行代码。"
    else:
        return "使用其它解释器执行代码。"


def w_trusted_script_invoked(f: Finding) -> str:
    """trusted-script-invoked

    只陈述"调用了这个可信脚本"。不补"未检查其内容"——那句话不随参数变化，也不给读者
    任何判断依据；也不暗示脚本的效果已知。
    """
    if f.target:
        return f"调用可信的脚本 {f.target}。"
    return "调用可信的脚本。"


def w_execution_content_unavailable(f: Finding) -> str:
    """execution-content-unavailable

    **只陈述发现：这段要执行的代码内容拿不到。**

    不补"由于当前证据强度只查元数据…"这类档位细节。那看起来像内部诊断，而且当文案被模型读到
    时，它会去纠结"是不是我参数没给对"，而不是处理眼前的调用。

    两种情形，句式不同：

    * `operation` 是**解释器名** (`python3`、`node`) ——"无法判断将由 python3 执行的代码内容"；
    * `operation` 是**文件** (`artifact`) ——"由…执行"就不通了，该说"无法判断将要运行的文件内容"。

    用 `f.operation_text` (翻译过的) 而不是 `f.operation` (原始代码) ，否则卡片上会出现
    "无法判断将由 artifact 执行的代码内容" 这种半英文句子。
    """
    if f.interpreters:
        return f"无法判断将由 {f.interpreters} 执行的代码内容。"
    action = f.operation_text
    if action:
        return f"无法判断{action}操作的具体效果。"
    return "无法判断将被执行的代码内容。"


def w_privilege_escalation(f: Finding) -> str:
    """privilege-escalation"""
    return "包含提权操作。"


def w_errors_suppressed(f: Finding) -> str:
    """errors-suppressed"""
    return "错误消息被屏蔽。"


def w_runtime_code_loading(f: Finding) -> str:
    """runtime-code-loading"""
    return "包含动态执行的代码。"


def w_network_request(f: Finding) -> str:
    """network-request

    两个来源：shell 里的 `curl`，以及 `web_fetch` 工具。

    **知道什么就写什么。** `web_fetch` 的参数里永远有 URL，所以永远写得出站点
     (`向 example.com 发送网络请求。`) ；shell 里 `curl` 的目标是变量时才知道不到了，那时才退到
    不含对象的说法 (`可能会发起网络请求。`) ——那句话只说"会联网"，因为除了这个确实一无所知。
    """
    target = f.list(f.get("destinations")) or f.get("url") or ""
    if f.get("fetch_kind"):
        host = f.get("host")
        if host:
            return f"向 {host} 发送网络请求。"
        if target:
            return f"向 {target} 发送网络请求。"
    if target:
        return f"向 {target} 发起网络请求。"
    return "可能会发起网络请求。"


def w_download_content(f: Finding) -> str:
    """download-content

    `fetch_kind == "heavy"` 是 `web_fetch` 那个"这地址会返回大段 HTML"的情形。

    **有更省的同源端点时就写出来** (`github.com 可能返回大段 HTML，建议用 api.github.com 等替代。`) ：
    那是**随参数变化**的信息——同一个 host 换成 API 端点就完全不需要这条提示，读者据此能判断
    该不该放行。没有可靠端点时只说会返回大段 HTML，不编一个地址。
    """
    target = f.list(f.get("destinations")) or f.get("url") or ""
    if f.get("fetch_kind") == "heavy":
        host = f.get("host")
        alternative = f.get("alternative")
        if host and alternative:
            return f"{host} 可能返回大段 HTML，建议用 {alternative} 等替代。"
        if host:
            return f"{host} 可能返回大段 HTML。"
        if target:
            return f"{target} 可能返回大段 HTML。"
        return "该地址可能返回大段 HTML。"
    if target:
        return f"从 {target} 下载内容。"
    return "可能从网络下载内容。"


def w_tool_needs_confirmation(f: Finding) -> str:
    """tool-needs-confirmation (`interrupt_agent`、`subagent` 这类参数看不出版本行为的工具) 

    **一句话，只写"这个工具在做什么"。** 不加"该工具需要人工确认"——等级标签 `[注意]` 已经说了；
    也不补"中间状态会丢失"这类后果——那些内容**不随参数变化**，每次都一样，读者读完得不到任何
    判断依据，只是多读一行。
    """
    note = f.get("note") or ""
    if note:
        return f"{note}。"
    tool = f.get("tool") or "该工具"
    return f"{tool} 需要人工确认。"


def w_search_request(f: Finding) -> str:
    """search-request (`web_search`) 

    **知道什么就写什么**：参数里就有查询词，所以把查询词写出来。
    `发起联网搜索。` (不带对象) 只留给"除了会联网一无所知"的情形，这里不是。
    """
    queries = f.get("queries")
    text = f.list(queries)
    if text:
        return f"发起联网搜索：{text}。"
    note = f.get("note") or ""
    if note:
        return f"{note}。"
    return "发起联网搜索。"


def w_credentials_sent(f: Finding) -> str:
    """credentials-sent"""
    if f.destinations:
        return f"向 {f.list(f.destinations)} 发送的内容可能包含凭据。"
    else:
        return "可能将凭据通过网络发送。"


def w_publish_risk(f: Finding) -> str:
    """publish-risk"""
    if f.destinations:
        return f"即将推送本地文件{f.publish_note}。"
    return "把本地文件推送到远端。"


def w_environment_modified(f: Finding) -> str:
    """environment-modified"""
    if f.variables:
        return f"环境变量 {f.list(f.variables)} 被修改。"
    return "修改环境变量。"


def w_environment_value_output(f: Finding) -> str:
    """environment-value-output

    输出的是**调用方提供的环境变量**，不是脚本自己赋的值，也不是凭据命中——凭据由
    `credentials-exposed` 负责。句子只写这层事实，不追加“可能泄露”之类的推测。
    """
    if f.variables:
        return f"输出调用方环境变量 {f.list(f.variables)} 的值。"
    return "输出调用方提供的环境变量。"


def w_readonly_assignment_failed(f: Finding) -> str:
    """readonly-assignment-failed"""
    if f.variables:
        return f"向只读变量 {f.variables} 的赋值没有生效，后续仍用旧值。"
    return "向只读变量赋值没有生效，后续仍用旧值。"


def w_package_install(f: Finding) -> str:
    """package-install"""
    if f.package_note:
        return f"安装 {f.package_note}。"
    return "安装新的软件包。"


def w_package_change(f: Finding) -> str:
    """package-change"""
    if f.package_note:
        return f"卸载或改写已安装的 {f.package_note}。"
    return "卸载或改写已安装的软件包。"


def w_system_settings_change(f: Finding) -> str:
    """system-settings-change"""
    return "修改系统设置。"


def w_service_change(f: Finding) -> str:
    """service-change

    `action` 可能是 `sc create` 这种带前缀的复合动作。前缀在服务语境里不加信息 (那句话本身就
    在说"系统服务或者计划任务") ，所以剥掉，只用动词；`sc` 在 `ACTION_PREFIX_TEXT` 里已经是
    空串，其余前缀 (`volume`、`system`…) 本来属于容器语境，落在这里就丢掉。
    """
    action = f.action or "修改"
    for prefix in ACTION_PREFIX_TEXT.values():
        if prefix and action.startswith(prefix):
            action = action[len(prefix):]
            break
    # `new-service` 翻成“新建服务”；后面已经要接“系统服务或者计划任务”，
    # 再保留“服务”会变成“新建服务系统服务…”。
    if action.endswith("服务"):
        action = action[:-2]
    if not action:
        action = "修改"
    if f.targets:  # 用复数键：service-change 给的是 targets 列表
        return f"{action}系统服务或者计划任务 {f.targets}。"
    return f"{action}系统服务或者计划任务。"


def w_force_process_termination(f: Finding) -> str:
    """force-process-termination"""
    if f.target:
        return f"强制终止进程 {f.target}。"
    return "强制终止进程。"


def w_machine_power_change(f: Finding) -> str:
    """machine-power-change"""
    if f.target:
        return f"包含关机或重启操作 {f.target}。"
    return "包含关机或重启操作。"


def w_raw_device_read(f: Finding) -> str:
    """raw-device-read"""
    if f.target:
        return f"直接读取块设备 {f.target}。"
    return "直接读取块设备。"


def w_raw_device_write(f: Finding) -> str:
    """raw-device-write"""
    if f.target:
        return f"直接向块设备 {f.target} 上写入数据。"
    else:
        return "直接往块设备上写入数据。"


def w_unmount_drive(f: Finding) -> str:
    """unmount-drive"""
    if f.target:
        return f"卸载文件系统 {f.target}。"
    return "卸载文件系统。"


def w_docker_change(f: Finding) -> str:
    """docker-change"""
    action = f.action or "修改"
    if f.target:
        return f"{action}容器资源 {f.target}。"
    return f"{action}容器资源。"


def w_volume_format(f: Finding) -> str:
    """volume-format"""
    if f.target:
        return f"格式化卷 {f.target}，该卷上的全部数据会被清空。"
    return "格式化卷，该卷上的全部数据会被清空。"


def w_backup_delete(f: Finding) -> str:
    """backup-delete"""
    if f.target:
        return f"删除卷 {f.target} 的卷影副本，回滚与恢复的依据随之消失。"
    return "删除卷影副本，回滚与恢复的依据随之消失。"


def w_free_space_wipe(f: Finding) -> str:
    """free-space-wipe"""
    if f.target:
        return f"擦除卷 {f.target} 的空闲空间，被删的数据无法恢复。"
    return "擦除磁盘空闲空间，被删的数据无法恢复。"


def w_event_log_clear(f: Finding) -> str:
    """event-log-clear"""
    if f.target:
        return f"清除事件日志 {f.target}。"
    return "清除事件日志。"


def w_registry_change(f: Finding) -> str:
    """registry-change"""
    if f.target:
        return f"修改注册表项 {f.target}。"
    return "修改注册表。"


def w_security_policy_change(f: Finding) -> str:
    """security-policy-change"""
    if f.target:
        return f"修改安全策略 {f.target}。"
    return "修改安全策略。"


def w_account_change(f: Finding) -> str:
    """account-change"""
    if f.target:
        return f"创建或修改账户 {f.target}。"
    return "创建或修改账户。"


def w_git_push(f: Finding) -> str:
    """git-push"""
    if f.target:
        return f"把提交推送到远端 {f.target}。"
    return "把提交推送到远端。"


def w_git_commit(f: Finding) -> str:
    """git-commit"""
    if f.target:
        return f"在仓库 {f.target} 创建本地 Git 提交。"
    return "创建本地 Git 提交。"


def w_git_config_modified(f: Finding) -> str:
    """git-config-modified"""
    scope = f"{f.scope}作用域的" if f.scope else ""
    keys = f"配置项 {f.keys}" if f.keys else " Git 配置"
    return f"{f.action or '修改'}了{scope}{keys}。"


def w_git_history_rewrite(f: Finding) -> str:
    """git-history-rewrite

    分析器分本地与远端两种：本地是 `commit --amend` 或显式历史过滤，远端是强推/删除 ref。
    两种说法不能混：`--amend` 说成“对远端做强制更新”会让读者以为要动远端。
    """
    scope = f.get("history_scope")
    options = f.get("options") or []
    repo = f"仓库 {f.target} " if f.target else "当前仓库"
    if scope == "local":
        if "--amend" in options:
            return f"改写{repo}的最近一次本地提交。"
        return f"改写{repo}的本地提交历史。"
    what = f" {f.refspecs} " if f.refspecs else "代码仓库"
    where = f"远端 {f.target} " if f.target else "远端"
    return f"对{where}的{what}做强制更新或删除。"


def w_git_reset_state_unavailable(f: Finding) -> str:
    """git-reset-state-unavailable"""
    return "强制重置当前仓库的状态。"


def w_modify_analyzer_config(f: Finding) -> str:
    """modify-analyzer-config"""
    if f.target:
        return f"修改判定器或审批机制的配置文件 {f.target}。"
    return "修改判定器或审批机制的配置文件。"


def w_modify_sensitive_file(f: Finding) -> str:
    """modify-sensitive-file"""
    if f.target:
        return f"修改敏感文件 {f.target}。"
    return "修改敏感文件。"


def w_sql_unresolved(f: Finding) -> str:
    """sql-unresolved"""
    subject = f.sql_parts or ""
    why = f.reason_text or "无法解析"
    index = f"第 {f.statement_index} 条 SQL 语句" if f.statement_index else "有 SQL 语句"
    where = f" ({subject}) " if subject and subject != "语句" else ""
    return f"{index}{where}{why}。"


def w_sql_row_change(f: Finding) -> str:
    """sql-row-change"""
    subject = f.sql_parts or "数据行"
    action = f.action or "修改"
    index = f"第 {f.statement_index} 条 SQL 语句" if f.statement_index else "有 SQL 语句"
    return f"{index}{action}了 {subject}{f.where_note or ''}。"


def w_sql_schema_change(f: Finding) -> str:
    """sql-schema-change"""
    subject = f.sql_parts or "表结构"
    action = f.action or "变更"
    index = f"第 {f.statement_index} 条 SQL 语句" if f.statement_index else "有 SQL 语句"
    return f"{index}{action}了 {subject}。"


def w_sql_truncate(f: Finding) -> str:
    """sql-truncate"""
    subject = f.sql_parts or "表"
    action = f.action or "截断"
    index = f"第 {f.statement_index} 条 SQL 语句" if f.statement_index else "有 SQL 语句"
    return f"{index}{action}了 {subject}，表内数据会全部消失。"


def w_sql_remove_schema(f: Finding) -> str:
    """sql-remove-schema"""
    subject = f.sql_parts or "结构对象"
    action = f.action or "删除"
    index = f"第 {f.statement_index} 条 SQL 语句" if f.statement_index else "有 SQL 语句"
    return f"{index}{action}了 {subject}，依赖它的查询会失效。"


def w_sql_privilege_change(f: Finding) -> str:
    """sql-privilege-change"""
    who = f.principals or "某用户"
    what = f.privileges or "部分"
    subject = f.sql_parts or ""
    index = f"第 {f.statement_index} 条 SQL 语句" if f.statement_index else "有 SQL 语句"
    where = f"，对象是 {subject}" if subject else ""
    return f"{index}把 {what} 权限授予了 {who}{where}。"


def w_sql_create_identity(f: Finding) -> str:
    """sql-create-identity"""
    subject = f.sql_parts or "数据库身份"
    action = f.action or "创建"
    index = f"第 {f.statement_index} 条 SQL 语句" if f.statement_index else "有 SQL 语句"
    return f"{index}{action}了 {subject}。"


def w_sql_drop_object(f: Finding) -> str:
    """sql-drop-object"""
    subject = f.sql_parts or "数据库对象"
    action = f.action or "删除"
    index = f"第 {f.statement_index} 条 SQL 语句" if f.statement_index else "有 SQL 语句"
    return f"{index}{action}了 {subject}，其中的数据一并消失。"


def w_unknown_command(f: Finding) -> str:
    """unknown-command（LOW / HIGH 两档）

    * `LOW` —— 命令**确实是**一条命令，只是分析器没建模它的行为（`frobnicate --all`）；
    * `HIGH` —— 命令位置上的**文本根本不像命令名**（`"print(hello)"`、`"llama cpp"`）。这几乎
      总是**引号没写对**：引号提前闭合，后面那截残句被当成了命令名。分析器给的
      `data.reason` 是 `suspicious_command_name`。

    两档必须说不同的话：`[警告] 包含未知命令 print(hello)。` 和 `[提示] 包含未知命令 frobnicate。`
    除了标签一模一样，读者看不出前者其实是"你的命令写坏了"——而这正是这条 HIGH 存在的理由。

    **HIGH 不再按 `name_pattern` 细分。** 空格、语法字符、控制字符、无名字符听起来像四种毛病，
    但对读者只有一件事要做：检查引号闭合的位置。分成四句只会让卡片的长短随输入抖动。分析器仍然
    在 `data.name_pattern` 里给这个分类（排错时有用），判定器只是不用它组织句子。
    """
    name = f.tool_name
    if name and f.get("reason") == "suspicious_command_name":
        return f"命令位置上的 {name} 看上去不像一个命令，检查引号闭合的位置。"
    resolved = f.get("command_resolved")
    # 字段**缺失**不能当成"未解析"：那会白白丢掉一个已知的命令名。只有明确的 False 才算未解析。
    if name and (resolved is None or resolved):
        return f"包含未知命令 {name}。"
    # 命令名来自展开：知道是哪个变量就写出来（`variables` 里有），否则只说到"取决于展开"。
    names = f.list(f.get("variables"))
    if names:
        return f"命令名取决于变量 {names} 的展开结果，无法确定要执行什么。"
    if name:
        return "命令名取决于展开结果，无法确定要执行什么。"
    return "包含未知命令。"


def w_tool_invoked(f: Finding) -> str:
    """tool-invoked"""
    if f.tool_name and f.tool_category_text:
        return f"{f.tool_category_text} {f.tool_name} 被调用。"
    if f.tool_name:
        return f"{f.tool_name} 被调用。"
    if f.tool_category_text:
        return f"某个{f.tool_category_text}被调用。"
    return "调用了未知软件。"


def w_unknown_option(f: Finding) -> str:
    """unknown-option"""
    if f.get('option'):
        return f"存在未知选项 {f.get('option')}。"
    else:
        return "存在未知选项或参数。"


def w_unresolved_value(f: Finding) -> str:
    """unresolved-value

    上游现在把变量名放进了 `data.variables`，所以这条能说出是**哪个**变量定不下来，
    两条不同原因的 finding 不会再印成同一句话。

    原因代码有两个来源：`data.reason` (有就用) ，以及**上游把它当标题用的那几种情况**——
    例如 `cat "$FILE"` 的标题就是 `missing_variable`。后者靠 `f.reason_code` 取出来，
    所以这类 finding 能说清"引用的变量未定义"。

    **有候选值时不写"无法确定"。** 那两句会自相矛盾：

        无法确定实际的值 (可能的值：p (a 或 b) ) 。      ← 前半句被后半句否掉了

    候选值本身就是"这个值会是什么"的答案 (只是不唯一) ，所以直接陈述候选，不再说"无法确定"。
    """
    action = f"在{f.operation_text}时，" if f.operation_text else ""
    conditions = f.condition_text() if f.conditions else ""
    where = f"，且仅在{conditions}成立" if conditions else ""
    why = translate_reason(f.reason_code) if f.reason_code else "取值取决于运行结果"
    if f.variables:
        subject = f" {f.variables} 的值"
    else:
        subject = "实际的值"
    # 因上限而放弃候选要说 (`unresolved_reasons`) ：否则读者会以为分析器不会算，而不是
    # "到了配置的上限就停手、宁可说不知道"。
    limit = f.unresolved_reasons
    because = f"，因为{limit}" if limit else ""
    # **只有真拿到候选明细时才说"可能是…"**：`possible: true` 但没有明细时，说"可能是它"
    # 会和附注的"取值未知"打架 (`可能是它取值未知。`) 。那种情况仍然是"无法确定"。
    if f.possible_values:
        # 有候选：把候选做成**变量名的内联注解**，直接嵌进"无法确定 X 的值"这句里。
        # 不要另起一句 (`…。可能的值：F 可能为 a 或 b。`) ——前一句不提 F，后一句突然出现
        # 它的取值，读起来莫名其妙。也避开"取值"重复。
        target = f"变量 {f.possible_annotation} 的值" if f.possible_names else "实际的值"
        return f"{action}由于{why}{where}，无法确定{target}。"
    return f"{action}由于{why}{where}，无法确定{subject}{because}。"


def w_unsupported_syntax(f: Finding) -> str:
    """unsupported-syntax"""
    t = ""
    if f.operation_text:
        t += f"在{f.operation_text}时，"
    if f.reason_text:
        t += f"由于{f.reason_text}，"
        if f.loop or f.branch:
            t += "且仅在" + f.condition_text() + "成立，"
    elif f.loop or f.branch:
        t += "由于仅在" + f.condition_text() + "成立，"
    t += "无法确定实际的执行效果。"
    return t


def w_analysis_unavailable(f: Finding) -> str:
    """analysis-unavailable

    `data` 里有 `shell` 和 `reason`，用上说清"是哪个前端、为什么不可用"，比笼统一句
    "命令格式异常"更能定位问题——它也可能是选错了 shell 名。
    """
    shell = f.get("shell")
    if shell:
        return f"终端 {shell} 不可用。"
    return "命令格式异常。"


# ── 路径调用 (1.6.0)  ────────────────────────────────────────────────────────
#
# 这四条回答的是"用路径去调用某个东西时会发生什么"。它们把 `Unknown Command` 的很大一部分
# 接了过来：`/usr/bin/git` 不该说"我不认识这条命令"，而该说"用绝对路径调用了 git"。


def _path_facts(f: Finding) -> tuple[str, str]:
    """路径规则共用的两部分：怎么写的路径，和"有没有核对过磁盘"。

    返回 `(路径写法, 核对说明)` 两段而不是拼好的一句——因为中文里"核对说明"通常要放在句尾
    做附注 (`… (未核对磁盘) `) ，塞在中间会把句子读断。
    """
    path_type = PATH_TYPE_TEXT.get(str(f.get("path_type")), f.get("path_type")) or "路径"
    status = EVIDENCE_STATUS_TEXT.get(str(f.get("evidence_status")), "")
    if f.get("evidence_status") == "available":
        status = ""
    elif f.get("evidence_status") == "unavailable":
        status = "，但该路径无法访问"
    else:
        status = "，但该路径不存在"
    return str(path_type), status


def w_command_via_path(f: Finding) -> str:
    """command-via-path"""
    tool = "某个命令"
    if f.tool or f.command:
        tool = f" {f.tool or f.command}"
    path_type, status = _path_facts(f)
    head = f"用{path_type}调用{tool}"
    if f.target and f.target != f.command:
        return f"{head}，即 {f.target}{status}。"
    return f"{head}{status}。"


def w_executable_via_path(f: Finding) -> str:
    """executable-via-path"""
    name = "某个可执行文件"
    if f.tool or f.command:
        name = f" {f.tool or f.command}"
    path_type, status = _path_facts(f)
    head = f"用{path_type}运行{name}"
    if f.target and f.target != f.command:
        return f"{head}，即 {f.target}{status}。"
    return f"{head}{status}。"


def w_execute_target_missing(f: Finding) -> str:
    """execute-target-missing

    **只陈述发现。** 这条 finding 只有上游**确认了**目标不存在才会发出 (README：None 永远不会
    声称源文件不存在) ，所以"不存在"就是已经确认的事实，不需要再补"已核对磁盘"这类内部状态。

    那种括注恰恰有害：文案会被模型读到时，` (已核对磁盘) ` 读起来像一个诊断标记，模型容易把它
    当成"报错"而去找绕过路径。同理也不写"我查过了"——模型会理解成"我核查过、看不出问题"，然后
    换个说法重试。

    也不按 `evidence_status` 分岔成两句：同一件已确认的事实，不该因为证据档位不同而换一种说法
     ("不存在"和"无法验证…"是两句强度完全不同的话，混在一起读者无法判断哪句是结论) 。
    """
    target = "目标程序"
    if f.target or f.command:
        # 路径与"不存在"之间**要有空格**：不加会粘成 `absent.ps1不存在`，
        # 中文和拉丁路径挤在一起读不出边界。
        target = f" {f.target or f.command} "
    return f"要运行的{target}不存在。"


def w_execute_target_not_executable(f: Finding) -> str:
    """execute-target-not-executable"""
    target = "目标文件"
    if f.target or f.command:
        target = f" {f.target or f.command} "
    return f"试图运行的{target}不是可执行文件。"


def w_file_operation_unresolved(f: Finding) -> str:
    """file-operation-unresolved

    1.9.0 新增，**只在 Python 里出现**：`open`/`io.open`/`Path.open` 的**模式**、或 `os.open`
    的 **flags** 由运行时决定，于是"这是读还是写"定不下来。

    **候选值是变量名的内联注解。** 用户的目标句式：

        打开文件时的模式依赖于变量 f (可能为 0 或 1)，因此无法确定对该文件的具体操作模式

    反过来 (`…无法确定对该文件的具体操作模式。取值未知。`) 后面那句是多余的；而
    `…可能的值：f 可能为 0 或 1` 的后半截也重复了变量名。注解直接贴在变量名后面一次说清。

    上游**不给 `target`**，所以这句话说不出是哪个文件。不编一个出来。
    """
    annotation = f.possible_annotation
    if annotation:
        return f"打开文件时的模式依赖于变量 {annotation}，因此无法确定对该文件的具体操作模式。"
    # 没有候选明细：只知道有个变量定不下来，或者连变量名都没有。
    if f.variables:
        return f"打开文件时的模式取自变量 {f.variables}，因此无法确定对该文件的具体操作模式。"
    return "因此无法确定对打开的文件的具体操作模式。"


def w_analyzer_error(f: Finding) -> str:
    """analyzer-error

    `reason` 是分析器做不了这次检查的原因 (缺少解析器、cwd 风格不匹配、语法包没装…) 。
    说出来比笼统一句"分析失败"有用：其中有些是配置问题，读者能自己修。

    **句尾必须有句号。** `reason_text` 是个**从句** (`引用了未定义的变量`) ，不是完整句子，
    所以不能写成 `…失败: {why}` 收尾 —— 那样卡片上会没有句号。放进括号当附注，句子本身照常收尾。
    """
    why = f.reason_text if f.get("reason") else ""
    if why:
        return f"由于{why}，代码含义分析失败。"
    return "代码含义分析失败。"


# ── 判定器自有的 write / edit 检查 ──────────────────────────────────────────
#
# 这些句子以前写在 `filechecks.py` 里，现在统一到这里。数据由 `filechecks` 量好放 `data`，
# 所以句子能用上精确数字。`data.check` 是 `"write"` 还是 `"edit"`，用来分措辞。


def _is_edit(f: Finding) -> bool:
    return str(f.get("check") or "") == "edit"


def w_write_size(f: Finding) -> str:
    """write-size"""
    size = f.get("written_bytes")
    if size is None:
        return f"写入 {f.target}。"
    existing = f.get("existing_bytes")
    if existing is None:
        return f"将创建大小约为 {size} 字节的新文件 {f.target}。"
    return f"将写入 {size} 字节到 {f.target}（原文件 {existing} 字节）。"


def w_edit_size_change(f: Finding) -> str:
    """edit-size-change"""
    before = f.get("before_bytes")
    after = f.get("after_bytes")
    delta = f.get("delta_bytes")
    occurrences = f.get("occurrences")
    lines = f.get("lines", 0)
    if before is None or after is None:
        return f"编辑 {f.target}。"
    if isinstance(delta, int):
        change = "大小不变" if delta == 0 else (
            f"{'增加' if delta > 0 else '减少'} {abs(delta)} 字节")
        size_note = f"（{change}）"
    else:
        size_note = ""
    num_target = f"，替换了 {occurrences} 处" if occurrences and occurrences > 1 else ""
    return (f"编辑 {f.target} 后，文件从 {before} 字节变为 {after} 字节{size_note}，"
            f"共 {lines} 行{num_target}。")


def w_write_target_is_directory(f: Finding) -> str:
    """write-target-is-directory"""
    if _is_edit(f):
        return f"{f.target} 是目录，无法作为文件编辑。"
    return f"{f.target} 已经是一个目录，无法作为文件写入。"


def w_edit_target_missing(f: Finding) -> str:
    """edit-target-missing"""
    return f"要编辑的文件 {f.target} 不存在。"


def w_edit_target_not_utf8(f: Finding) -> str:
    """edit-target-not-utf8"""
    return f"要编辑的文件 {f.target} 不是 UTF-8 格式。"


def w_edit_target_unreadable(f: Finding) -> str:
    """edit-target-unreadable

    两种来源：查 `stat` 失败 (权限 / ACL / 沙箱拒绝) ，或者读内容失败。**两种情况都不说
    "不存在"**——"我没看到"和"确实没有"是两件事，后者由 `edit-target-missing` 负责。
    """
    why = f.get("reason") or "读取失败"
    if f.target:
        return f"读取 {f.target} 失败（{why}），无法确认本次修改的结果。"
    return f"读取目标文件失败（{why}），无法确认本次修改的结果。"


def w_write_target_unreadable(f: Finding) -> str:
    """write-target-unreadable (`write` 查不到目标状态) 

    `write` 不需要读内容，只需要知道"这个路径上有没有东西"。查不到就明说不知道——既不说会覆盖，
    也不说是新建，因为两者都可能。
    """
    why = f.get("reason") or "查询失败"
    if f.target:
        return f"查不到 {f.target} 的状态（{why}），无法判断这次是新建还是覆盖。"
    return f"查不到目标文件的状态（{why}），无法判断这次是新建还是覆盖。"


def w_edit_empty_fragment(f: Finding) -> str:
    """edit-empty-fragment"""
    return "没有给出要替换的文本。"


def w_edit_fragment_missing(f: Finding) -> str:
    """edit-fragment-missing

    `where` **不要带尾部空格**：模板里 `{f.target}{where} 中不存在` 已经有一个空格了，
    带上就叠成两个 (`…script.sh (30 字节)  中不存在`) 。
    """
    characters = f.get("characters")
    where = f"（{characters} 字节）" if characters else ""
    return f"待替换的片段在 {f.target}{where}中不存在，本次编辑大概率失败。"


def w_edit_fragment_ambiguous(f: Finding) -> str:
    """edit-fragment-ambiguous

    命中多处不是“歧义”：edit 工具会把所有命中一起替换。这里只提示“会全部替换”，
    并说清一共替换多少处，不要写成“只替换其中一处”。
    """
    occurrences = f.get("occurrences")
    if f.target and occurrences:
        return (f"待替换的片段在 {f.target} 中出现 {occurrences} 次，"
                f"本次编辑会全部替换这 {occurrences} 处。")
    if occurrences:
        return f"待替换的片段出现 {occurrences} 次，本次编辑会全部替换这 {occurrences} 处。"
    if f.target:
        return f"待替换的片段在 {f.target} 中出现多次，本次编辑会全部替换。"
    return "待替换的片段出现多次，本次编辑会全部替换。"


def w_edit_no_change(f: Finding) -> str:
    """edit-no-change"""
    if f.target:
        return f"待替换文本与替换文本一致，对 {f.target} 的这次编辑不会改变任何内容。"
    return "待替换文本与替换文本一致，这次编辑不会改变任何内容。"


def w_command_tool_mismatch(f: Finding) -> str:
    """command-tool-mismatch

    这条由 `policy._shell_decision` 产生 (工具名与命令语法不一致) ，文案在这里。数据里带
    `tool` 就说明是哪个工具。

    **不写"请确认要按哪种 shell 执行"。** 那是把选择权交回模型，而模型看到"请确认"最可能的
    反应是自己选一个、换个写法重试——正是要避免的行为。只陈述不一致这个发现就够了。
    同理不写"两侧的路径与转义规则不同"：那是解释，不是发现。
    """
    tool = f.get("tool")
    if tool:
        return f"调用的是 {tool} 工具，但命令的语法属于另一种 shell。"
    return "工具名与命令的语法不属于同一个 shell。"


RULE_WRITERS: dict[str, Any] = {
    # ── 文件系统 ────────────────────────────────────────────────────────
    "read-outside-workspace": w_read_outside_workspace,
    "write-outside-workspace": w_write_outside_workspace,
    "delete-inside-workspace": w_delete_inside_workspace,
    "delete-outside-workspace": w_delete_outside_workspace,
    "delete-workspace-root": w_delete_workspace_root,
    "delete-protected-root": w_delete_protected_root,
    "delete-after-failed-assignment": w_delete_after_failed_assignment,
    "delete-target-missing": w_delete_target_missing,
    "delete-variable-unresolved": w_delete_variable_unresolved,
    "delete-recursion-unresolved": w_delete_recursion_unresolved,
    # ── 环境与系统 ───────────────────────────────────────────────────────
    "write-variable-unresolved": w_write_variable_unresolved,
    # ── 文件系统 ────────────────────────────────────────────────────────
    "overwrite-existing-file": w_overwrite_existing_file,
    "permissions-too-broad": w_permissions_too_broad,
    "filesystem-selection-delete": w_filesystem_selection_delete,
    # ── 内容 ──────────────────────────────────────────────────────────
    "written-source-syntax-error": w_written_source_syntax_error,
    "credentials-read": w_credentials_read,
    "credentials-written": w_credentials_written,
    "credentials-exposed": w_credentials_exposed,
    "hardcoded-secret": w_hardcoded_secret,
    "prompt-injection-read": w_prompt_injection_read,
    "ingestion-inspection-incomplete": w_ingestion_inspection_incomplete,
    "unreadable-payload": w_unreadable_payload,
    "obfuscated-payload": w_obfuscated_payload,
    # ── 执行 ──────────────────────────────────────────────────────────
    "uses-interpreter": w_uses_interpreter,
    "trusted-script-invoked": w_trusted_script_invoked,
    "execution-content-unavailable": w_execution_content_unavailable,
    "privilege-escalation": w_privilege_escalation,
    "errors-suppressed": w_errors_suppressed,
    "runtime-code-loading": w_runtime_code_loading,
    # ── 网络 ──────────────────────────────────────────────────────────
    "network-request": w_network_request,
    "download-content": w_download_content,
    "credentials-sent": w_credentials_sent,
    "publish-risk": w_publish_risk,
    # ── 环境与系统 ───────────────────────────────────────────────────────
    "environment-modified": w_environment_modified,
    "environment-value-output": w_environment_value_output,
    "readonly-assignment-failed": w_readonly_assignment_failed,
    "package-install": w_package_install,
    "package-change": w_package_change,
    "system-settings-change": w_system_settings_change,
    "service-change": w_service_change,
    "force-process-termination": w_force_process_termination,
    "machine-power-change": w_machine_power_change,
    "raw-device-read": w_raw_device_read,
    "raw-device-write": w_raw_device_write,
    "unmount-drive": w_unmount_drive,
    "docker-change": w_docker_change,
    "volume-format": w_volume_format,
    "backup-delete": w_backup_delete,
    "free-space-wipe": w_free_space_wipe,
    "event-log-clear": w_event_log_clear,
    "registry-change": w_registry_change,
    "security-policy-change": w_security_policy_change,
    "account-change": w_account_change,
    # ── Git ─────────────────────────────────────────────────────────
    "git-commit": w_git_commit,
    "git-push": w_git_push,
    "git-config-modified": w_git_config_modified,
    "git-history-rewrite": w_git_history_rewrite,
    "git-reset-state-unavailable": w_git_reset_state_unavailable,
    # ── 环境与系统 ───────────────────────────────────────────────────────
    "modify-analyzer-config": w_modify_analyzer_config,
    "modify-sensitive-file": w_modify_sensitive_file,
    # ── SQL ─────────────────────────────────────────────────────────
    "sql-unresolved": w_sql_unresolved,
    "sql-row-change": w_sql_row_change,
    "sql-schema-change": w_sql_schema_change,
    "sql-truncate": w_sql_truncate,
    "sql-remove-schema": w_sql_remove_schema,
    "sql-privilege-change": w_sql_privilege_change,
    "sql-create-identity": w_sql_create_identity,
    "sql-drop-object": w_sql_drop_object,
    # ── 覆盖面 ─────────────────────────────────────────────────────────
    "unknown-command": w_unknown_command,
    "tool-invoked": w_tool_invoked,
    "unknown-option": w_unknown_option,
    "unresolved-value": w_unresolved_value,
    "unsupported-syntax": w_unsupported_syntax,
    "analysis-unavailable": w_analysis_unavailable,
    # ── 路径调用 ─────────────────────────────────────────────────────────
    "command-via-path": w_command_via_path,
    "executable-via-path": w_executable_via_path,
    "execute-target-missing": w_execute_target_missing,
    "execute-target-not-executable": w_execute_target_not_executable,
    # ── 文件操作无法确定 (1.9.0，Python 的 open 模式/flags) ─────────────
    "file-operation-unresolved": w_file_operation_unresolved,
    # ── 判定器自身 ───────────────────────────────────────────────────────
    "analyzer-error": w_analyzer_error,
    "write-size": w_write_size,
    "edit-size-change": w_edit_size_change,
    "write-target-is-directory": w_write_target_is_directory,
    "edit-target-missing": w_edit_target_missing,
    "edit-target-not-utf8": w_edit_target_not_utf8,
    "edit-target-unreadable": w_edit_target_unreadable,
    "write-target-unreadable": w_write_target_unreadable,
    "edit-empty-fragment": w_edit_empty_fragment,
    "edit-fragment-missing": w_edit_fragment_missing,
    "edit-fragment-ambiguous": w_edit_fragment_ambiguous,
    "edit-no-change": w_edit_no_change,
    "command-tool-mismatch": w_command_tool_mismatch,
    "cwd-outside-workspace": w_cwd_outside_workspace,
    "tool-needs-confirmation": w_tool_needs_confirmation,
    "search-request": w_search_request,
}


# ─────────────────────────────────────────────────────────────────────────────
# 渲染入口
# ─────────────────────────────────────────────────────────────────────────────

def _catalog_description(rule: str) -> str:
    """分析器自己为这条规则写的英文说明，用作没翻译时的兜底。"""
    global _CATALOG_DESCRIPTIONS
    if _CATALOG_DESCRIPTIONS is None:
        try:
            from analyzer_link import rule_catalog

            _CATALOG_DESCRIPTIONS = {
                str(entry.get("rule", "")): str(entry.get("description", ""))
                for entry in rule_catalog().get("rules", [])
            }
        except Exception:  # 分析器可能不在，兜底文案仍然可用
            _CATALOG_DESCRIPTIONS = {}
    return _CATALOG_DESCRIPTIONS.get(rule, "")


_CATALOG_DESCRIPTIONS: dict[str, str] | None = None


def render(finding: dict[str, Any]) -> str:
    """一条发现 -> 卡片上那一行的**全部内容** (不含等级前缀) 。

    判定器只负责在前面加 `序号. [等级] `，后面写什么完全由这里决定——包括要不要有
    "标题：描述" 这种结构。

    找不到文案时依次退到：分析器的英文说明、再退到一句"两边都没说明"。无论退到哪一层，
    规则名都会保留，方便你去查。
    """
    f = Finding(
        rule=str(finding.get("rule", "")),
        level=str(finding.get("level", "LOW")).upper(),
        data=dict(finding.get("data") or {}),
        evidence=tuple(finding.get("evidence") or ()),
        title=str(finding.get("title", "")),
        detail=str(finding.get("detail", "")),
    )
    writer = RULE_WRITERS.get(f.rule)
    if writer is None:
        described = _catalog_description(f.rule)
        if described:
            return f"{f.rule}: {described.rstrip('.')}"
        return f"未处理的规则名称: {f.rule}"
    line = writer(f)
    # Analyzer 1.16 keeps a bounded set of possible working directories. Each
    # surviving target gets its own finding with `possible: true`; the card must
    # not present that target as a certainty.
    if f.get("possible") is True and "可能" not in line:
        line = "可能" + line
    return line


def known_writers() -> frozenset[str]:
    return frozenset(RULE_WRITERS)

