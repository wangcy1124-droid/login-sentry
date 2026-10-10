# Login Sentry

面向小型 Web 应用与 Linux SSH 登录场景的轻量级登录异常监测与告警系统。

**Current status: Stage 5 API and dashboard**

已实现统一 `LoginEvent`、SSH/Web parser、SQLite `login_events` 与
`collector_offsets`、二进制增量读取、重启续读及一次性采集 CLI。
另已实现 failure_burst、multi_account、动态规则配置及一次性检测 CLI。
已实现持久化告警聚合、冷却、人工核查和事件追溯。
已实现 FastAPI 查询 API、SQL 统计聚合和 Jinja2 / ECharts Dashboard。
原有 `GET /api/health` 保持不变。尚未实现通知、认证或多用户管理。

## 技术栈与目标架构

技术栈：Python、FastAPI、SQLite、Python 正则表达式、ECharts、Linux、pytest。
无需 Docker 或外部数据库、消息队列。

Minimum supported runtime: Python 3.8

Recommended development runtime: Python 3.10+

保留 Python 3.8 兼容性，以便在 Ubuntu 20.04 类主机上轻量部署。

目标数据流（当前已实现采集、解析、统一事件、SQLite、检测、告警和查询展示）：

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
`db`、`models`、`services` 分别提供持久化、模型与采集编排，`api` 预留查询边界；
`templates`、`static` 预留前端资源。未来时间逻辑须支持确定时间注入。

## 本地安装

在仓库根目录执行（Linux / WSL，Python 3.8+，开发推荐 3.10+）：

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
python -m compileall app scripts
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

## 一次性增量采集

先按上文安装项目，在仓库根目录激活虚拟环境后执行：

```bash
python scripts/ingest_file.py --type web --path samples/web.log --database data/login-sentry.sqlite3
python scripts/ingest_file.py --type ssh --path samples/ssh.log --database data/login-sentry.sqlite3 --year 2026 --timezone +00:00
```

输出 `lines_read`、`events_inserted`、`ignored_lines`、`parse_errors`。
首次采集样例分别写入 Web 3 条、SSH 4 条事件；文件未变化时再次运行均为 0。
默认数据库为 `data/login-sentry.sqlite3`，首次打开自动幂等建表及索引。
自定义数据库的父目录须已存在。SSH 必须显式提供 year 和 timezone，
支持 `Z`、`+00:00`、`+08:00`、`-04:00`；负偏移使用 `--timezone=-04:00`。

采集器以 `rb` 读取，只在遇到 LF 后处理完整行（支持 CRLF）。UTF-8 无效字节
用 U+FFFD 替换，再交给 parser；不会按 Unicode 分隔符拆行。末尾无换行的
半行保持未消费，后续补齐后再处理。无关行推进偏移并计入 ignored；
`ParseError` 推进偏移并单独计数，避免坏行永久阻塞。其他异常向调用者传播。

每条完整行的可选事件插入与偏移更新使用同一个 SQLite 事务；数据库失败时
两者一起回滚，之前已提交的行保留。仓库写方法不自行 commit，由调用者管理
事务。采集器要求空闲、启用事务的连接。UTC 存储格式固定为带 6 位小数秒和
`+00:00` 的 ISO 时间，读取时恢复 aware UTC datetime 与枚举。
创建/更新时间由可注入 clock 提供；事件时间始终来自日志/显式 SSH 上下文。

状态键使用 `Path.resolve()` 的绝对路径，包含已打开文件描述符的 inode 与
下一读取位置的字节偏移。相同 inode 且文件大小不小于偏移时续读；大小小于
偏移时从 0 开始；inode 变化时读取当前路径的新文件。空文件或仅含半行的新
文件可保存偏移 0。负偏移/非法 inode 会报错，输入文件缺失不会自动创建。
两次内容完全相同的登录仍可分别存储，避免重复依靠持久化偏移而非事件唯一约束。

当前限制：同步一次性执行，假设每个数据库/来源工作流只有一个写入者；
不追读轮转后重命名的旧文件，也不处理动态符号链接轮转方案。若截断后已重新
增长到保存偏移以上，仅凭 inode/size 无法识别；并发写入中的任意截断亦不保证
无遗漏。保持同一来源的 parser 类型与 SSH 上下文稳定；本阶段没有后台轮询。

## 异常检测

```bash
python scripts/detect_anomalies.py --database data/login-sentry.sqlite3 --config config/default.toml
```

命令一次性评估已保存事件，输出规则、IP、实际事件数、不同用户名数、窗口起止
和 SQLite event_ids，最后输出 `matches=N`。不打印 raw_log，不写入告警。
数据库不存在时初始化空 schema 并输出 `matches=0`（父目录须存在）；空数据库
同样返回 0。重复检测相同数据库/config 输出一致，不保存检测状态。

默认配置：failure_burst 为 60 秒内至少 5 次失败；multi_account 为 300 秒内
失败尝试至少 4 个不同用户名。两条规则都仅计 FAILURE；成功登录不计数。
因此共享 NAT IP 下多个用户成功登录不会仅因账号多而触发。SSH/Web 合并按
规范化 source_ip 分组，支持 IPv4/IPv6，同一事件簇可以同时触发两条规则。

候选窗口 `[T - window_seconds, T]` 两端包含；边界恰好等于窗口时计入，
多 1 微秒则移出。每个 IP 输入按 timestamp/id 升序。算法使用双指针和活动
用户名计数表，每个 IP 线性扫描；不为每条事件重复生成重叠匹配：

1. 尚未达标时滑动左边界，移出过期失败。
2. 首次达标后固定当前最早事件，纳入仍在该时限内的后续失败。
3. 下一条超出时输出当前簇，从该下一条重新开始；不会重用前簇尾部生成重叠匹配。

这是有界、不重叠的贪心合并策略，每个匹配跨度不超过配置窗口；它不枚举所有
可能的重叠窗口。`window_start/end` 是实际纳入事件的最早/最晚时间，event_ids
按 timestamp/id 排序且簇内唯一。输出按 window_end、source_ip、rule_type 排序。

Python 服务 `app.services.detection.detect(connection, config, start_time=None,
end_time=None)` 可指定 aware 时间范围；转换为 UTC 后由参数化 SQLite 查询
筛选范围内失败。范围也是双端包含，范围外事件不作为窗口上下文补入。
未指定范围则评估全部已存失败，没有隐式当前时间截止。倒置范围和 naive 时间
会报错。纯规则函数只处理事件序列，不访问数据库或文件。

`config/default.toml` 的两个规则表要求 `enabled` 布尔值、正整数 window_seconds、
对应阈值和 cooldown_seconds；拒绝缺字段、未知字段、错误类型及 bool 冒充整数。修改 TOML 后下一次
加载即可生效；`enabled=false` 独立关闭对应规则。显式配置路径缺失或格式错误
直接报错，不回退。Python 3.8–3.10 使用轻量 tomli，3.11+ 使用标准库 tomllib。

## 告警聚合与人工核查

```bash
python scripts/process_alerts.py --database data/login-sentry.sqlite3 --config config/default.toml
python scripts/review_alert.py --database data/login-sentry.sqlite3 --alert-id 1 --status false_positive --note "shared office NAT"
```

处理命令先加载配置，再初始化数据库、检测和处理匹配。新空库输出全零统计。
输出 matches_seen、alerts_created、alerts_aggregated、duplicate_occurrences、links_added。
检测 CLI 仍然不写告警记录；schema 初始化会添加空的告警表。

fingerprint 是稳定文本 `rule_type|source_ip`，不同规则或 IP 分开处理。
failure_burst 严重度 medium、冷却 300 秒；multi_account 严重度 high、冷却
600 秒。配置中的 cooldown_seconds 必须是正整数，不接受 bool、缺字段或未知字段；
Python 配置对象保留默认冷却值，已有三参数构造仍兼容。

只选择同 fingerprint 最新（last_seen、id 降序）的 open/confirmed 告警。
新 occurrence 的 window_end <= last_seen + cooldown 时聚合，恰好边界包含，
多 1 微秒则新建。乱序旧匹配也归入最新活动告警，first_seen 取最小值，last_seen
取最大值，绝不倒退；不会回溯重组旧告警。冷却用于聚合，未实现任何通知发送。

occurrence_count 是不同 DetectionMatch 的数量，不是事件数量。occurrence key
使用规则、IP、UTC 窗口起止和排序后的真实事件 ID 的 JSON 做 SHA-256。
完全相同匹配重复运行、进程重启或人工关闭后再次运行均只计 duplicate_occurrences，
不递增次数、不增加链接。已有簇因追加事件或改配置而改变匹配身份时，是新的 occurrence；
链接取并集，即使匹配包含重叠事件也不重复链接。

每个 occurrence 的告警插入/更新、occurrence 写入、事件链接位于同一事务；任一步
失败全部回滚，之前已提交的 occurrence 保留。要求单写入者、空闲且启用事务的连接。
时间存储沿用固定 6 位小数 UTC；事件窗口来自匹配，元数据时钟可注入。
初始化旧数据库只添加表/索引，不删除原有事件和偏移。

核查允许 open → confirmed/false_positive/resolved，以及 confirmed →
false_positive/resolved。拒绝同状态重复操作、关闭后重开及其他转换。
confirmed 聚合仍保持 confirmed；false_positive/resolved 为关闭历史，新的
occurrence 创建 open 告警，不复用关闭记录。核查不删除事件、occurrence 或链接。
review_note 允许 None、空字符串（原样保存）及最多 2000 字符普通文本。

`AlertRepository.list_events(alert_id)` 返回带真实 SQLite ID 的 StoredLoginEvent，
按 timestamp/id 排序，可沿 `record.event.raw_log` 追溯原始日志。
`alerts` 不重复保存 raw_log；`alert_event_links` 使用复合主键和外键防止重复/孤立链接。

## 查询 API 与 Dashboard

启动后访问 `http://127.0.0.1:8000/`：三张告警统计卡、7 日趋势折线图、
来源 IP 柱状图、规则分布饼图，以及带状态筛选和分页的告警表。
点击“查看事件”可读取关联原始日志；页面只读，人工核查继续使用既有 CLI。
页面使用 Jinja2 与固定版本 ECharts 5.6.0 CDN，不使用前端框架。
CDN 需要浏览器可联网；加载失败时仍显示统计卡和告警表并提示原因。
没有自动轮询，点击刷新获取最新数据。

API 默认使用 `data/login-sentry.sqlite3`。可指定与采集 CLI 相同的数据库：

```bash
LOGIN_SENTRY_DATABASE=/absolute/path/events.sqlite3 python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

父目录须存在；首次查询不存在的数据库时初始化空 schema。请求使用独立连接，
同一响应内的读取处于一个事务；除幂等建表外不写业务记录。健康检查与页面本身
不打开数据库。无认证，默认示例仅监听本机；不要将含原始日志的 API 直接公开。

| Endpoint | 参数 / 返回 |
| --- | --- |
| `GET /api/alerts` | 可选 status、rule_type、source_ip；limit 默认 50（1–100）、offset 默认 0（非负）；返回 items、total |
| `GET /api/alerts/{alert_id}` | alert 与 events；含真实事件 ID 和 raw_log |
| `GET /api/events/{event_id}` | id、timestamp、source_type、source_ip、username、result、raw_log |
| `GET /api/statistics/summary` | 总告警数及四种状态数量 |
| `GET /api/statistics/trend` | days 默认 7（1–366），每日 date/count |
| `GET /api/statistics/sources` | limit 默认 10（1–100），来源 IP/count |
| `GET /api/statistics/rules` | rule_type/count |

列表按 last_seen DESC、id DESC，total 为过滤后分页前总数；IP 过滤支持规范化
IPv4/IPv6。状态与规则类型使用现有枚举值。参数非法返回 422，详情不存在返回 404。
时间返回带时区的 ISO 8601，source_type 与 result 沿用小写枚举（ssh/web、success/failure）。
链接事件按 timestamp、ID 升序。字符串在页面以纯文本显示。

统计计数单位是告警行，不是 occurrence_count，也不是事件数。summary、sources、rules
覆盖全部历史告警；sources 按数量降序、IP 升序，rules 按规则名排序。
trend 按 first_seen 的 UTC 日期统计，从今天前 days−1 天的 00:00 到明天
00:00（左闭右开），缺失日期补零；默认当前时间可在 create_app 的 clock 参数中
注入以便测试。各统计使用 SQL GROUP BY，不将完整告警表加载到 Python。

## 配置与运行数据

`config/default.toml` 当前仅加载 `[rules]`。其他配置段仍预留，数据库路径由 CLI 提供。
`data/` 存放运行数据，除 `.gitkeep` 外不提交 Git；`samples/`
保存脱敏样例，`scripts/` 提供采集 CLI，`tests/unit/` 与 `tests/integration/`
包含模型、解析器、数据库、采集、检测与 CLI 测试；
`tests/scenarios/` 包含正常输错、连续失败、共享 IP 与窗口边界四类持久化场景测试。禁止提交凭据和运行日志。

## 后续开发

尚未实现真实通知、认证和多用户管理。检测本身仍只返回匹配，
独立告警服务负责持久化与核查。

具体阶段与顺序由 ChatGPT 主审查窗口决定。Stage 5 提交并推送后停止，
审查通过并收到下一阶段指令后才继续。服务器只拉取 GitHub exact commit SHA
进行独立测试和运行验证。角色及修改纪律见 `AGENTS.md`。
