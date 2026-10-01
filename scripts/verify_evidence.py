#!/usr/bin/env python3
"""离线证据包复核命令行（不依赖 HTTP 服务，不访问业务数据库）。

在复核机上直接对导出的证据包（.zip 或内联 .json）重算覆盖、X.509 与撤销
结论，只用包内材料：

    python -m scripts.verify_evidence approval-2-plan-3-evidence.zip
    python -m scripts.verify_evidence evidence.json

退出码：
    0 一致（consistent）
    2 不一致（inconsistent，差异写入 stdout 的 JSON）
    1 包本身非法（缺项/指纹不符/版本不符/非法时间等，错误码写入 JSON）
"""
from __future__ import annotations

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import evidence


def _load(path: str) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    if path.lower().endswith(".zip") or data[:2] == b"PK":
        return evidence.package_from_zip(data)
    return evidence.package_from_json_bytes(data)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m scripts.verify_evidence <evidence.zip|evidence.json>",
              file=sys.stderr)
        return 1
    try:
        package = _load(argv[1])
        result = evidence.verify_package(package)
    except evidence.EvidenceError as exc:
        print(json.dumps({"result": "error", "code": exc.code, "detail": exc.message},
                         ensure_ascii=False, indent=2))
        return 1
    # stdout 只保留结论与差异（不回显整份 PEM 材料）
    summary = {
        "result": result["result"],
        "approval_id": result["approval_id"],
        "plan_id": result["plan_id"],
        "domain": result["domain"],
        "eval_start": result["eval_start"],
        "eval_end": result["eval_end"],
        "differences": result["differences"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if result["result"] == "consistent" else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
