---
name: dsh-peer-link
description: 通过 DSH 互联插件（dsh-peer-link）把任务交给局域网里另一台已配对机器上的 DeepSeek Harness 执行，例如在 Windows 上跑命令、查那台机器的文件、环境或已装软件，以及续接、查看、停止对端会话。当用户提到另一台电脑、Windows、对端或 peer，要在那台机器上做什么时使用。需要当前环境有 subagent_peer 或 peer_dsh 工具。
---

# 委派到对端 DSH

对端是另一台机器上完整的 DSH agent，有那台机器的 shell、文件和工具。本机只收发文本。

## 前提

- `subagent_peer`（委派）和 `peer_dsh`（管理）由 dsh-peer-link 插件提供，只在装了它的 DSH 里有。两个都没有就停下，告诉用户需要在 DSH 里安装并启用该插件；不要自己去连对端的 HTTP 接口，请求必须用配对密钥签名。
- 不确定有哪些机器、是否在线时，先 `peer_dsh action=peers`。

## 选哪个工具

| 场景 | 用法 |
| --- | --- |
| 一般委派（默认） | `subagent_peer`。每个子代理对应对端一个会话，结果以完成通知送回；期间可以做别的事，不要轮询。 |
| 发给非默认的那台机器 | `peer_dsh action=run peer=<名称>`。`subagent_peer` 总是发往插件设置里的默认对端（只配对一台时就是它）。 |
| 一两句就能答完、要当场拿结果 | `peer_dsh action=run`，同步等待，默认最多 600 秒（`wait_seconds` 可调）。 |
| 续接不是由子代理开的对端会话 | `peer_dsh action=run session_id=<id>`。 |
| 看对端会话原文、列会话、停止 | `peer_dsh action=read` / `sessions` / `cancel`。 |
| 用户想自己看、自己操作对端 | 不用工具。告诉用户点侧边栏底部的「对端设备」（或子代理会话标题栏的「在 <对端> 上查看」），会在浏览器里打开对端的 DSH 网页。 |

## 写委派任务

- 对端看不到当前对话。`prompt` 要自成一体：目标、必要背景、对端机器上的绝对路径（Windows 写 `D:\proj`）、期望的汇报格式。
- 插件会自动附加"无人值守、自行决策并汇报"的说明，不用重复。
- 只读查询要写明"只查询，不要安装、修改或删除"。
- 对端会话往往是完全访问权限，Windows 上还可能以 Administrator 运行。安装、删除、改系统配置这类操作，先和用户确认再委派。
- 要在对端某个目录里工作：用 `subagent_peer` 时把绝对路径写进任务；用 `peer_dsh action=run` 新开会话时可传 `cwd`。

## 拿结果与续接

- 回复末尾有 `[peer-link] remote session <id> on <peer>`。向用户汇报时说明是在哪台机器上执行的；之后要直接查看或续接这个会话就用这个 id。
- 追问或补充：`send_message` 给该子代理，消息会进同一个对端会话，上下文保留。子代理还在运行时发的消息，会立即转给对端正在进行的那一轮。
- 对端在提问：回复里出现 `The remote agent is waiting for an answer:`。需要用户拿主意的先问用户，再用 `send_message`（子代理）或 `peer_dsh action=run` 同一 `session_id` 回答；这段文字会作为那次提问里每个问题的回答。
- 停止子代理会同时中止对端当前那一轮。
- `peer_dsh` 返回 `still-running`：稍后用 `action=read` 查看，不必重发任务。
- 结果看起来不是对任务的回答时，用 `peer_dsh action=read session_id=<id>` 看对端原文核实。

## 常见问题

- **对端 offline 或 lost contact**：对端 DSH 没运行、不在同一局域网，或防火墙挡了端口。"may still be running" 表示对端可能还在跑，稍后 `read`。
- **Windows 上命令以 `0xC0000142`（3221225794）失败，或任务卡住不动**：对端会话处在沙箱里或在等审批。请用户在 Windows 端的插件设置里把「对端会话的权限预设」设为 `danger-full-access`（安装后的授权弹窗选"允许"也行）。只对之后新开的会话生效，所以要重新委派。
- **`specify a peer: A, B`**：配对了多台但没设默认对端。可以改用 `peer_dsh action=run peer=<名称>`，或请用户在设置页选默认对端。
- **`bad signature (secret mismatch?)`**：配对已失效（例如对方重装后密钥变了），请用户重新配对。
- **`clock skew too large`**：两台机器时钟相差超过 5 分钟，请用户同步系统时间。
- **图片、附件传不过去**：插件只传文本。需要文件时让对端自己按路径读，或把内容写进任务。
- **「对端设备」里提示对方未开启共享或版本过旧**：请用户在对方机器的插件设置里打开「共享网页界面」，或把对方的 dsh-peer-link 升级到 0.4.0 以上。

## 配对

配对码里有密钥，不要让用户把它贴进对话。请用户在 设置 → 插件 → DSH 互联 里粘贴对方的配对码；或者把码文件拷到本机，再 `peer_dsh action=pair code=<码文件的绝对路径>`。
