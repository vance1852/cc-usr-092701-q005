# 澄序诊所运营服务

澄序是一套面向医疗美容与体重管理门诊的离线服务端应用。它记录患者授权、临床评估、诊疗计划、预约履约、复诊随访、处置事件和费用流水，供多个诊所团队在同一业务规则下协作。患者资料采用分域授权，重要业务操作保留不可变审计记录。

## 环境

需要 Python 3.11 或更高版本。运行时只使用 Python 标准库和 SQLite，不需要单独启动数据库或其他服务。

## 测试

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```sh
python3 -m compileall -q src tests
```

## 启动服务

首次运行先创建诊所和负责人，密码会在终端内安全提示，不会写入命令历史：

```sh
PYTHONPATH=src python3 -m careflow initialize --database careflow.sqlite3 --clinic 澄序门诊 --timezone Asia/Shanghai --owner 负责人姓名
```

随后启动接口：

```sh
PYTHONPATH=src python3 -m careflow.api --database careflow.sqlite3 --host 127.0.0.1 --port 8080
```

服务以 JSON 提供诊所、患者、授权、评估、计划、预约、耗材追溯、随访、不良事件和运营汇总接口。`GET /health` 返回进程与数据库状态；其他路由的参数和返回结构见 `docs/api.md`。登录后使用短期 Bearer 凭据，诊所编号通过 `X-Clinic-ID` 提供。此服务不写访问日志中的请求路径或请求正文。

## 数据库检查

```sh
PYTHONPATH=src python3 -m careflow check-db --database careflow.sqlite3
```

该命令运行 SQLite 完整性检查，不输出患者资料。

## 目录

- `src/careflow/`：应用、领域规则、存储、权限与 HTTP 服务。
- `tests/`：核心业务、边界条件、事务和接口验收。
- `docs/`：运营概念与接口说明。

数据库文件由服务进程创建。备份前应停止写入，并保留 SQLite 文件及其审计记录。
