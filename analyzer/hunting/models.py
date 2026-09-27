from dataclasses import dataclass
from datetime import datetime


HUNTING_FIELDS = {
    "timestamp",
    "source",
    "event_type",
    "username",
    "source_ip",
    "host",
    "message",
    "raw_log",
    "failed_attempts",
}

HUNTING_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "greater_than",
    "less_than",
    "greater_than_or_equal",
    "less_than_or_equal",
}

HUNTING_SORT_FIELDS = HUNTING_FIELDS


@dataclass
class HuntingQuery:
    field: str
    operator: str
    value: str


@dataclass
class HuntingQueryGroup:
    queries: list[HuntingQuery]
    logic: str = "AND"


@dataclass
class HuntingTimeRange:
    start: datetime
    end: datetime


@dataclass
class HuntingSearch:
    conditions: HuntingQuery | HuntingQueryGroup | None = None
    time_range: HuntingTimeRange | None = None
    limit: int = 100
    sort_by: str = "timestamp"
    sort_order: str = "desc"