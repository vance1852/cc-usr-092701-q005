"""标识符与幂等键校验。"""

import re
import uuid

from .errors import ValidationError

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def require_id(value: str, name: str = "编号") -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValidationError(f"{name}格式无效")
    return value


def require_idempotency_key(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 160:
        raise ValidationError("幂等键不能为空且不得超过 160 个字符")
    return value.strip()
