"""业务时钟抽象，便于稳定处理本地日界和过期状态。"""

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FrozenClock:
    def __init__(self, value: datetime):
        if value.tzinfo is None:
            raise ValueError("冻结时钟必须包含时区")
        self._value = value

    def now(self) -> datetime:
        return self._value

    def set(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("冻结时钟必须包含时区")
        self._value = value
