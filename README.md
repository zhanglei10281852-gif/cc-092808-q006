# 司法鉴定检材流转与复核服务

本项目是面向司法鉴定机构的 Python 后端服务，用于登记委托或移送案件、接收带封识的检材、记录保管位置与流转、执行专业检验、安排复核并处理环境和质量告警。案件、检材、检验记录和领用审批都保存在本地 SQLite 中，关键写入带版本或幂等键，适合在单个 Linux 应用容器内运行。

## 运行环境

- Python 3.11
- FastAPI 与 Uvicorn
- SQLite 3，由 Python 标准库提供

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `data/forensics.db`，也可以通过 `FORENSICS_DATABASE_PATH` 指向其他 `.db`、`.sqlite` 或 `.sqlite3` 文件。

## 初始化与启动

```bash
python -m app.cli init-db
python -m app.cli check-db
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查为 `GET /api/system/health`。首次使用可调用 `POST /api/auth/bootstrap` 创建管理员，再通过 `POST /api/auth/login` 取得 Bearer 会话令牌。鉴定业务接口统一位于 `/api/forensics`。

## 测试与构建检查

```bash
python -m pytest
python -m compileall -q app tests
```

下面两条命令分别检查 HTTP 入口和完整的入库演示链路：

```bash
python -m app.cli smoke
python -m app.cli demo
```

## 业务边界

- `app/forensics/cases.py` 管理委托机构、案件档案、委托资料与受理状态。
- `app/forensics/custody.py` 管理检材、库位容量、容器摆放、流转、领用和冻结。
- `app/forensics/examinations.py` 管理检验规程、取样、观察记录、检验结果与复核日程。
- `app/forensics/quality.py` 管理温湿度读数、偏离告警和检材领用审批。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。会话令牌只保存摘要，审计记录不保存明文密码或令牌。

### 父子检材与分取守恒

- 不带 `parent_specimen_id` 的登记是普通到案检材，沿原入口登记，`initial_quantity` 即初始可用量，不能借父标识凭空增量。
- 带 `parent_specimen_id` 的登记只能是一次原子分取，必须同时提供 `expected_parent_version`、`idempotency_key` 和 `business_reason`。系统在同一事务内校验同一案件、来源未耗尽/未销毁、未被冻结、版本一致且分取数量不超过来源可用量；成功后扣减来源（来源版本递增）、建立子检材封识，并写入父子双方的 `分取` 流水与不可变的 `specimen_aliquots` 谱系记录（含分取前后数量、业务理由、操作者）。
- 同一业务键重试且请求指纹一致时返回最初的子检材且不重复扣减；请求内容变化返回 409 冲突。并发分取由条件更新（版本 + 可用量）保证不会超量。
- 谱系记录和子检材的来源关系受触发器保护，不允许更新、删除或改写；子检材一旦被摆放、检验等引用，外键限制同样阻止删除。
- `GET /api/forensics/specimens/{id}` 在 `aliquot_origin`/`aliquots` 中返回分取前后数量、理由与操作者；`GET /api/forensics/specimens/{id}/reconcile` 的 `lineage` 段对整条谱系（含多代分取）给出一致的守恒结果：到案初始量 = 谱系现存可用量 + 离开谱系的外部流水。
