"""初始配置及无 PHI 数据库检查命令。"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from .db import Database
from .errors import CareflowError
from .service import Careflow


def build_parser():
    parser = argparse.ArgumentParser(prog="careflow", description="澄序诊所运营服务管理命令")
    subparsers = parser.add_subparsers(dest="command", required=True)
    bootstrap = subparsers.add_parser("initialize", help="原子创建首个诊所和负责人")
    bootstrap.add_argument("--database", default="careflow.sqlite3")
    bootstrap.add_argument("--clinic", required=True)
    bootstrap.add_argument("--timezone", required=True)
    bootstrap.add_argument("--owner", required=True)
    check = subparsers.add_parser("check-db", help="执行 SQLite 内部一致性检查")
    check.add_argument("--database", default="careflow.sqlite3")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "initialize":
            first = getpass.getpass("设置负责人密码：")
            second = getpass.getpass("再次输入负责人密码：")
            if first != second:
                parser.error("两次输入的密码不一致")
            result = Careflow(args.database).initialize_clinic(args.clinic, args.timezone, args.owner, first)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            print("请妥善保存负责人编号；访问凭据应通过 /auth/token 接口短期获取。")
            return 0
        database = Database(args.database)
        result = database.health()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 2
    except CareflowError as exc:
        print(json.dumps({"error": exc.code, "message": exc.message}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
