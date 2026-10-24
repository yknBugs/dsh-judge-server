# dsh-judge-server

给 [`dsh-manual-approval`](https://github.com/yknBugs/dsh-manual-approval) 插件用的判定服务器。
插件在 Manual 模式下把**单次工具调用** POST 过来，服务器返回 `approve` / `ask` / `deny` 和一段
中文说明，插件把说明显示在审批卡片上。

本仓库只包含判定服务器本身：工具分派、`write` / `edit` / `read` 的目标检查、等级到判定的映射、
中文文案，以及 HTTP 接口。shell 命令和源码内容的语义分析交给
[`command_inspector`](https://github.com/yknBugs/python-command-inspector)；这里不重复它的规则目录。

服务器默认只绑定回环地址。它**不执行任何命令**，不保存会话状态，每个请求独立判定。

## 配合插件使用

在插件的规则里新增一条 `judge` 动作：

| 字段 | 值 |
| --- | --- |
| `url` | `http://127.0.0.1:8791/dsh-judge` |
| `body` | 留空；插件默认发送的请求体就是本服务器的输入 |
| `decisionPath` | `decision` |
| `reasonPath` | `reason` |

插件默认请求体：

```json
{
  "session_id": "…",
  "working_space": "D:\\projects\\app",
  "cwd": "D:\\projects\\app\\src",
  "tool": "pwsh",
  "args": [{ "name": "command", "value": "ls" }]
}
```

如果启动服务器时设置了 `--token` 或 `DSH_INSPECTOR_TOKEN`，在规则的请求头
（`headersText`）里加一行：

```text
x-manual-approval-token: <token>
```

服务器返回：

```json
{"decision": "ask", "reason": "1. [注意] 中断另一个 agent。"}
```

插件侧的字段含义、超时和失败回退见插件 README 的“联网判断 / Network judge”一节。判定器只负责
给出结论和理由；任何失败都应该让插件把调用交回给人，而不是静默放行。

## 跑起来

要求 Python 3.11+，并且能 import 到 `command_inspector`。先安装分析器：

```sh
# 先安装分析器；路径按你的 checkout 调整
cd ../python-command-inspector
pip install -e ".[bash,windows,javascript,sql]"
```

按实际会用到的 shell 选 extras：`bash` 对应 bash，`windows` 对应 PowerShell，`javascript` 和
`sql` 用于检查被写入的 JS/SQL 内容。CMD 和 Python 不需要额外依赖。

然后回到本仓库启动服务器：

```sh
python server.py                                  # 127.0.0.1:8791
python server.py --host 127.0.0.1 --port 8791
python server.py --always-ask                     # 每条都问
python server.py --logging                        # 写 log/
python server.py --print-token                    # 生成一个 token 后退出
```

没有安装分析器时，也可以用 `--analyzer` 或环境变量 `COMMAND_INSPECTOR_SRC` 指向它的 checkout：

```sh
python server.py --analyzer ../python-command-inspector
```

服务器启动时会检查分析器；**分析器不可用就拒绝启动**，因为一个无法分析的判定器会把“没检查”
变成“没问题”。某个 shell 前端缺失时服务器仍会启动，但对应的调用会报 `analysis-unavailable`；
在默认 `--skip-safe` 下它会交给人。

## 命令行选项

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `--host` | `DSH_INSPECTOR_HOST` 或 `127.0.0.1` | 监听地址；非回环地址必须同时给 token |
| `--port` | `DSH_INSPECTOR_PORT` 或 `8791` | 监听端口 |
| `--token` | `DSH_INSPECTOR_TOKEN` 或空 | 设置后要求请求头带 `x-manual-approval-token` |
| `--print-token` | — | 用 `secrets.token_urlsafe(32)` 生成 token 并退出 |
| `--analyzer` | `COMMAND_INSPECTOR_SRC` 或空 | 分析器 checkout 路径；会把该目录及其 `src/` 加进 `sys.path` |
| `--verbose` | 关 | 把每次判定摘要写到 stderr |
| `--logging` | 关 | 把请求、判定文字、决策和等级上限写入项目下的 `log/` |
| `--always-ask` | — | 自动批准上限 `NEVER` |
| `--skip-safe` | 默认 | 自动批准上限 `NONE`，只放行没有实质发现的调用；统计类发现不算实质发现 |
| `--auto-approve` | — | 自动批准上限 `LOW` |
| `--report-warning` | — | 自动批准上限 `MEDIUM` |
| `--approve-all` | — | 自动批准上限 `HIGH` |
| `--llama-url` / `--llama-model` / `--llama-timeout` / `--llama-policy` | 见“本地模型” | 可选的本地模型补充说明 |

自动批准选项可以重复出现，**后面的覆盖前面的**。

## HTTP 接口

### `POST /dsh-judge`

请求体是 JSON 对象，最大 4 MiB；启用 token 时必须带 `x-manual-approval-token`。

- 请求体不是 JSON、不是对象，或 `content-length` 非法：`400`。
- 请求体为空或过大：`413`。
- token 不匹配：`401`。
- 判定过程出现未捕获异常：仍返回 `200`，但决定是 `ask`，文案为
  `1. [注意] 判定器执行异常：…`。

`working_space` 和 `cwd` 不是一回事：

| 字段 | 含义 |
| --- | --- |
| `working_space` | 用户最初指定的项目目录，整个会话不变；用来判断“有没有跳出工作区” |
| `cwd` | 这次调用**现在**所在的目录；用来解析相对路径 |

`working_space` 缺省时退回 `cwd`。

`args` 推荐使用 `[{"name": …, "value": …}]` 的有序数组。也接受以工具名为键的
`{cwd, "<tool>": {…}}` 形状；那种情况下两个目录字段是同一个值。

### `GET /healthz`

返回行为版本、当前自动批准上限、分析器规则数、判定器有中文文案的规则数、分析器能力，以及本地
模型是否启用。适合在启动后确认“现在回答请求的是哪一版、用的是哪个分析器”。

## 判定

三个决定：

| 决定 | 含义 |
| --- | --- |
| `approve` | 自动放行 |
| `ask` | 交给人确认，卡片展示发现 |
| `deny` | 直接拒绝，只有 `[拦截]` 会走到这里 |

默认 `--skip-safe` 下，按最严重的**实质性**发现决定：

| 最严重发现 | 默认决定 | 卡片标签 |
| --- | --- | --- |
| 无实质发现 | `approve` | — |
| `LOW` | `ask` | `[提示]` |
| `MEDIUM` | `ask` | `[注意]` |
| `HIGH` | `ask` | `[警告]` |
| `BLOCK` | `deny` | `[拦截]` |

`BLOCK` 不受任何自动批准上限影响：它是判定器唯一的 `deny`。

五个自动批准参数设的是**上限**：最严重发现不超过上限就 `approve`，超过就 `ask`。因此
`--auto-approve` 会放行 `LOW`，`--report-warning` 会放行 `MEDIUM` 及以下，`--approve-all` 会放行
`HIGH` 及以下。放宽上限时，卡片仍会列出发现——自动放行不等于不告诉你。

几个边界：

- 完全没有发现时返回 `approve`，文案是 `本次调用未发现风险。`；只有统计类发现时也是
  `approve`，但卡片会列出那些统计。
- `--always-ask` 下没有发现也返回 `ask`，文案仍是这句话。
- 对工具表里那组“直接 `approve`”的工具，`--always-ask` **不会**把它们改成询问；它们直接
  `approve`，也不检查内容。
- 未知工具、缺少必要参数的 shell / write / fetch 调用会直接 `ask`。分析器检查失败会以
  `[注意]` 报出；默认 `--skip-safe` 下也是 `ask`，但放宽到 `--report-warning` 及以上时，
  它和普通 `MEDIUM` 一样落在上限内。
- `write-size`、`edit-size-change`、`edit-no-change` 是统计类发现：它们会显示，但不参与
  “最严重发现”的比较；只有它们时仍可能 `approve`，但在 `--always-ask` 下会交给人。

一句话：在默认 `--skip-safe` 下，`approve` 只表示“检查跑过且没有需要拦住的东西”（或工具本身
改不了任何状态）。放宽上限后，落在上限内的发现也会被放行——放行不等于没发现。

## 各工具怎么判

| 工具 | 处理 |
| --- | --- |
| `pwsh` / `powershell` / `cmd` / `bash` / `sh` / `shell` / `terminal` | 交给分析器；工具名直接决定 shell 方言 |
| `ask_user_question`、`create_goal`、`exit_plan_mode`、`get_goal`、`job_list`、`job_output`、`list_agents`、`present`、`todo_*`、`update_goal`、`send_message`、`schedule_*` | 直接 `approve`，不检查内容 |
| `interrupt_agent`、`job_kill`、`skill`、`subagent`、`subagent_fork`、`workflow`、`ralph` | 一条 `[注意]`，默认 `ask` |
| `web_search` | 一条 `[提示]`，写出查询词 |
| `read` / `read_image` / `glob` / `grep` | 只检查触及范围和凭据类文件名，不解释内容 |
| `write` / `edit` | 检查目标，并分析写入/修改后的内容 |
| `working_directory` | 省略 `cd` 按零发现处理；`cd` 跳出工作区时 `[注意]` |
| `web_fetch` | 普通页面 `[提示]`；可能返回大段 HTML 时 `[提示]`；只有存在更省的同源端点时才 `[注意]`，并写出端点 |
| 未登记的工具名 | `ask`，说明判定器没有它的行为模型 |

### shell

工具名直接映射方言，命令取 `command`、`cmd` 或 `script` 参数。命令文本和工具名明显不一致时
（例如 bash 工具收到 PowerShell 命令），会额外报一条 `[注意]`，然后继续分析。

#### 未知命令的两档

`unknown-command` 有 `[提示]` 和 `[警告]` 两档：

- `[提示] 包含未知命令 frobnicate。`：命令确实是一条命令，只是判定器没有它的行为模型。
- `[警告] 命令位置上的 print(hello) 看上去不像一个命令，检查引号闭合的位置。`：命令位置上的
  文本不像命令名（`"print(hello)"`、`"llama cpp"`），通常意味着引号提前闭合，后面的残句被当成了
  命令名。

后者是 `HIGH`：默认 `--skip-safe` 和 `--report-warning` 下都会 `ask`，只有 `--approve-all`
才会自动放行。分析器的 `name_pattern` 只留在 `data` 里供排错，不改变卡片句子。

### write / edit

两者都先检查目标路径：

- 目标在工作区外；
- 目标是目录、不可读，或无法确认状态；
- `write` 覆盖已有文件、写入字节数；
- `edit` 目标不存在、不是 UTF-8、片段为空、片段找不到、修改前后字节数变化；命中多处时会报告一条 LOW，并说明会全部替换这些命中。

`write` 的正文和 `edit` 修改后的结果，如果扩展名/文件名/shebang 表明它是可执行或可查询的文本
（shell、PowerShell、CMD、Python、JavaScript、SQL），会再送进分析器检查内容。其他文件按数据处理，
不强行解释。

### read / glob / grep

只回答两件事：读取范围是否在工作区外，以及目标名是否像凭据存储（`.env`、`id_rsa`、`.ssh/`、
`credentials.json` 等）。不读取、不解释文件内容。临时目录里的读取不单独报“工作区外”。

### working_directory

`cd` 会先折叠 `..` 再和 `working_space` 比较；落点在工作区外时 `[注意]`。只读当前目录（不传
`cd`）不改变任何状态，按零发现处理。

### web_search / web_fetch

`web_search` 的发现里带查询词；判定器不执行搜索。`web_fetch` 会写出目标站点：普通页面是
`[提示]`，整页 HTML 是 `[注意]`；遇到有更省端点的站点时会给出建议，例如 `github.com` 页面可以
改用 `api.github.com`。判定器不抓取页面，只根据 URL 判断。

## 卡片格式

`reason` 是一行一条发现：

```text
序号. [标签] 句子
```

- 发现按严重程度从高到低排列。
- 渲染后完全相同的行会合并，并在句号前加 `（共 N 处）`。
- 候选值作为变量名的**内联注解**出现，不另起一句。

真实格式示例：

```text
1. [提示] 读取工作目录外的 /etc/hostname。
2. [提示] 无法对将要读取的内容进行完整检查。
```

```text
1. [拦截] 删除目标 / 包含关键系统目录。
```

```text
1. [提示] 删除目标依赖于变量 A (可能为 b.txt 或 a.txt) 且可能删除工作目录内的文件 /work/b.txt。
2. [提示] 删除目标依赖于变量 A (可能为 b.txt 或 a.txt) 且可能删除工作目录内的文件 /work/a.txt。
```

```text
1. [注意] 中断另一个 agent。
```

零发现时没有编号：

```text
本次调用未发现风险。
```

未知工具也没有编号：

```text
未知工具「mystery」：判定器没有它的行为模型，无法代为放行。
```

句子由 `writers.py` 生成，等级前缀由 `policy.py` 添加；要改文案就改 `writers.py`。

## 日志

`--logging` 会把每次请求写进项目目录下的 `log/YYYY-MM-DD.log`，每条记录包含：

- 原始请求体；
- 判定文字；
- 决定和当时的自动批准上限。

`approve` 的调用也记——“放行了什么”和“拦下了什么”一样是审计对象。

日志只用于排查和审计，**不是判定的一部分**；写失败只往 stderr 说一句，不影响这次判定。
日志包含完整命令、路径和 session id，属于本机敏感数据，不要提交。

`--verbose` 只把决定摘要写到 stderr，不落盘。

## 本地模型

可选，纯装饰，**不参与判定**。设置了 `--llama-url`（或 `DSH_INSPECTOR_LLAMA_URL`）后启用：

```sh
python server.py --llama-url http://127.0.0.1:12345 --llama-model <id> --llama-policy on
```

- 只在有发现时咨询；零发现的调用不会发给模型。
- 只发这次调用本身，不发发现清单，也不发文件内容。
- 返回的说明附在卡片末尾，标注为“仅供参考，不参与判定”。
- 任何失败（端点没起、超时、返回 HTML、返回无法解析的内容）都当作没有意见，判定不受影响。
- `--llama-policy off` 可以关掉，即使已经配置了 URL。
- `--llama-timeout` 默认 25 秒；`--llama-model` 省略时会尝试从端点的 `/v1/models` 读取模型 id。

环境变量：`DSH_INSPECTOR_LLAMA_URL`、`DSH_INSPECTOR_LLAMA_MODEL`、
`DSH_INSPECTOR_LLAMA_TIMEOUT`、`DSH_INSPECTOR_LLAMA_POLICY`。

## 文件

```text
server.py        HTTP 服务、命令行、日志与 token
policy.py        工具分派、等级到判定的映射、卡片行组装
tools.py         工具名到家族/方言的映射
writers.py       卡片上每一句中文文案
rules_zh.py      等级标签、判定器自有规则名、统计类规则集合
analyzer_link.py 分析器的定位、导入与异常转结论
filechecks.py    write/edit 的目标检查与内容分析
readchecks.py    read/glob/grep 的触及范围与凭据检查
language.py      按扩展名/文件名/shebang 判断内容语言
localmodel.py    可选的本地模型补充说明
```

## 安全边界

- 默认只监听回环地址；监听非回环地址时如果没有 `--token`，服务器拒绝启动。
- token 是共享密钥，HTTP 不加密；不要把服务暴露到不可信网络。
- 判定器能回答“某个路径是否存在/是否可读”，因此没有 token 时不要对外提供。
- 服务器不执行命令、不保存会话状态；但为了判断目标和内容，会做只读的文件检查。
- 除可选的本地模型外，判定器不主动联网；`web_search` / `web_fetch` 只描述调用，不代发请求。
- 日志包含完整请求，可能含凭据、路径和会话 id，应按敏感数据保管。
- 判定器的结论是建议；最终是否放行由插件和用户决定。它不是沙箱，也不是通用静态分析器。
