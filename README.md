# Login Sentry

面向小型 Web 应用与 Linux SSH 登录场景的轻量级登录异常监测与告警系统。

**Current status: Stage 0 bootstrap**

目前仅实现 FastAPI 最小应用、`GET /api/health` 和 pytest smoke test。
配置文件与其他目录仅为后续阶段预留；尚未实现日志解析、数据库、检测、
告警或 Dashboard。

## 技术栈与目标架构

技术栈：Python、FastAPI、SQLite、Python 正则表达式、ECharts、Linux、pytest。
无需 Docker 或外部数据库、消息队列。当前最低 Python 版本为 3.10；
服务器版本尚待独立验证，不假设服务器使用 Python 3.12。

目标数据流（尚未实现）：

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

## 配置与运行数据

`config/default.toml` 仅预留后续配置，目前不加载。预留默认规则为
60 秒内 5 次失败、300 秒内尝试 4 个不同账号，规则均未实现。
`data/` 存放未来运行数据，除 `.gitkeep` 外不提交 Git；`samples/`
预留脱敏样例，`scripts/` 预留辅助脚本，`tests/unit/` 和
`tests/scenarios/` 预留单元与场景测试。禁止提交凭据和运行日志。

## 后续开发

后续范围包括 Web/SSH 解析、增量采集、统一事件、SQLite 持久化、
可配置窗口与阈值、失败频率和多账号规则、告警聚合及冷却、原始日志追溯、
人工核查与误报标记、查询 API 和 ECharts 展示。规则测试将覆盖正常输错、
连续失败、共享 IP 和窗口边界。

具体阶段与顺序由 ChatGPT 主审查窗口决定。Stage 0 提交并推送后停止，
审查通过并收到下一阶段指令后才继续。服务器只拉取 GitHub exact commit SHA
进行独立测试和运行验证。角色及修改纪律见 `AGENTS.md`。
