# Login Sentry

面向小型 Web 应用与 Linux SSH 登录场景的轻量级登录异常监测与告警系统。

**Current status: Stage 1 parsers**

已实现统一 `LoginEvent`、SSH parser、Web parser、parser 单元测试及脱敏样例。
原有 FastAPI `GET /api/health` 与 smoke test 保持不变。
尚未实现 collector、SQLite、detection、alert、API query 或 Dashboard。

## 技术栈与目标架构

技术栈：Python、FastAPI、SQLite、Python 正则表达式、ECharts、Linux、pytest。
无需 Docker 或外部数据库、消息队列。当前最低 Python 版本为 3.10；
服务器版本尚待独立验证，不假设服务器使用 Python 3.12。

目标数据流（当前仅实现 parsers 与统一事件，其他环节尚未实现）：

```text
Web / SSH logs → collectors → parsers → normalized events
                                      ↓
                               detectors → alerts
                                      ↓
                                    SQLite
                                      ↓
                                FastAPI → ECharts
```

`collectors` 负责增量读取；`parsers` 负责解析与规范化；`detectors`
负责可独立测试的规则；`alerts` 负责聚合、冷却和人工核查。
`db`、`models`、`services`、`api` 预留持久化、模型、编排与查询边界；
`templates`、`static` 预留前端资源。未来时间逻辑须支持确定时间注入。

## 本地安装

在仓库根目录执行（Linux / WSL，Python 3.10+）：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
```

若 Debian / Ubuntu 缺少 venv/ensurepip，需先由环境管理员安装与 Python
版本匹配的 `python3-venv` 包。测试依赖包含 pytest 和 TestClient 使用的
httpx。FastAPI 暂限 0.115 系列，以保留与 httpx TestClient 的兼容组合；
依赖兼容性以实际安装后的 smoke test 为准。

## 启动

```bash
source .venv/bin/activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

另一个终端验证：

```bash
curl http://127.0.0.1:8000/api/health
```

预期：`{"status":"ok","service":"login-sentry"}`。使用 Ctrl+C 停止服务。

## 测试

```bash
source .venv/bin/activate
python -m compileall app
pytest -q
git diff --check
```

## 登录日志解析规范

解析器是纯函数，不读取文件或保存数据：成功返回 `LoginEvent`，不相关行返回
`None`，识别到目标但字段损坏时抛出 `app.parsers.base.ParseError`。
事件使用不可变 dataclass，来源为 `SourceType.SSH/WEB`，结果为
`LoginResult.SUCCESS/FAILURE`，timestamp 必须带有效时区，IP 由解析器验证
并规范化。`raw_log` 仅去除末尾 CR/LF，保留其他空白。

Web 格式固定，字段顺序为 username、ip、result，不允许重复或额外字段：

```text
2026-10-05T13:42:12+08:00 LOGIN username=alice ip=192.0.2.10 result=SUCCESS
```

`LOGIN`、`SUCCESS`、`FAILURE` 区分大小写。用户名允许 ASCII 字母、数字、
`_`、`-`、`.`、`@`，且不可为空。IP 支持 IPv4/IPv6。timestamp 使用
`YYYY-MM-DDTHH:MM:SS[.ffffff]` 加 `Z` 或 `±HH:MM`，小数秒支持 1–6 位；
缺时区或无效日期会报错。字段间允许空白，但事件必须占一行。

SSH 支持传统 syslog `sshd[PID]` 的 Accepted password、Accepted publickey、
Failed password（含 invalid user）。publickey 的 ssh2 后附加元数据只保留于
原始日志，不作解释。其他认证方式及连接状态消息返回 `None`。
SSH timestamp 的年份与时区必须由调用者提供，不读取当前时间，也不推断跨年：

```python
from datetime import timezone
from app.parsers.ssh import parse_ssh_line
from app.parsers.web import parse_web_line

ssh = "Oct  5 13:42:12 host sshd[1001]: Failed password for root from 192.0.2.10 port 52111 ssh2"
event = parse_ssh_line(ssh, year=2026, tzinfo=timezone.utc)
web = "2026-10-05T13:42:12+08:00 LOGIN username=alice ip=198.51.100.20 result=SUCCESS"
event = parse_web_line(web)
```

`samples/ssh.log` 和 `samples/web.log` 使用 RFC 5737 / RFC 3849 文档地址，
包含成功、失败和无关行；均为虚构日志，不含真实基础设施数据。

## 配置与运行数据

`config/default.toml` 仅预留后续配置，目前不加载。预留默认规则为
60 秒内 5 次失败、300 秒内尝试 4 个不同账号，规则均未实现。
`data/` 存放未来运行数据，除 `.gitkeep` 外不提交 Git；`samples/`
保存脱敏样例，`scripts/` 预留辅助脚本，`tests/unit/` 包含模型和解析器测试，
`tests/scenarios/` 预留后续场景测试。禁止提交凭据和运行日志。

## 后续开发

后续范围包括增量采集、SQLite 持久化、
可配置窗口与阈值、失败频率和多账号规则、告警聚合及冷却、原始日志追溯、
人工核查与误报标记、查询 API 和 ECharts 展示。规则测试将覆盖正常输错、
连续失败、共享 IP 和窗口边界。

具体阶段与顺序由 ChatGPT 主审查窗口决定。Stage 1 提交并推送后停止，
审查通过并收到下一阶段指令后才继续。服务器只拉取 GitHub exact commit SHA
进行独立测试和运行验证。角色及修改纪律见 `AGENTS.md`。
