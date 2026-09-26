"""请求边界的规范化与临床记录校验。"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from .errors import ValidationError

_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_PHONE = re.compile(r"^[+0-9 ()-]{7,24}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def text(value: Any, field: str, *, minimum: int = 1, maximum: int = 500, strip: bool = True) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field}必须是文本")
    result = value.strip() if strip else value
    if len(result) < minimum or len(result) > maximum:
        raise ValidationError(f"{field}长度必须在 {minimum} 至 {maximum} 个字符之间")
    if "\x00" in result:
        raise ValidationError(f"{field}包含无效字符")
    return result


def optional_text(value: Any, field: str, *, maximum: int = 1000) -> str | None:
    if value is None or value == "":
        return None
    return text(value, field, minimum=0, maximum=maximum)


def timestamp(value: Any, field: str = "时间") -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field}必须为 ISO 8601 时间") from exc
    else:
        raise ValidationError(f"{field}必须为 ISO 8601 时间")
    if parsed.tzinfo is None:
        raise ValidationError(f"{field}必须包含时区")
    return parsed.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parsed_timestamp(value: str, field: str = "时间") -> datetime:
    return datetime.fromisoformat(timestamp(value, field).replace("Z", "+00:00"))


def calendar_date(value: Any, field: str = "日期") -> str:
    try:
        return date.fromisoformat(value).isoformat()
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"{field}必须为 YYYY-MM-DD") from exc


def decimal_value(value: Any, field: str, *, minimum: str | None = None, maximum: str | None = None) -> float:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValidationError(f"{field}必须为数字") from exc
    if not number.is_finite():
        raise ValidationError(f"{field}必须为有限数字")
    if minimum is not None and number < Decimal(minimum):
        raise ValidationError(f"{field}不得低于 {minimum}")
    if maximum is not None and number > Decimal(maximum):
        raise ValidationError(f"{field}不得高于 {maximum}")
    return float(number)


def integer(value: Any, field: str, *, minimum: int = 0, maximum: int = 10**9) -> int:
    if isinstance(value, bool):
        raise ValidationError(f"{field}必须为整数")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field}必须为整数") from exc
    if str(result) != str(value) and not isinstance(value, int):
        raise ValidationError(f"{field}必须为整数")
    if result < minimum or result > maximum:
        raise ValidationError(f"{field}范围无效")
    return result


def choice(value: Any, field: str, choices: set[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ValidationError(f"{field}取值无效", details={"allowed": sorted(choices)})
    return value


def email(value: Any) -> str:
    result = text(value, "邮箱", maximum=254).lower()
    if not _EMAIL.fullmatch(result):
        raise ValidationError("邮箱格式无效")
    return result


def phone(value: Any) -> str:
    result = text(value, "手机号", maximum=24)
    if not _PHONE.fullmatch(result):
        raise ValidationError("联系方式格式无效")
    return result


def digest(value: Any, field: str = "摘要") -> str:
    result = text(value, field, minimum=64, maximum=64)
    if not _DIGEST.fullmatch(result):
        raise ValidationError(f"{field}必须为 SHA-256 十六进制值")
    return result


def object_value(value: Any, field: str, *, allowed: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{field}必须为对象")
    if allowed is not None:
        extra = set(value) - allowed
        if extra:
            raise ValidationError(f"{field}包含未知字段", details={"fields": sorted(extra)})
    return value


def request_digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def require_match(actual: int, expected: int, entity: str) -> None:
    if actual != expected:
        from .errors import Conflict

        raise Conflict(f"{entity}已被其他操作更新", details={"expected_version": expected, "actual_version": actual})
