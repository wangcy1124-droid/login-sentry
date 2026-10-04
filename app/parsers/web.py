"""Parse the project's fixed, case-sensitive Web login log format."""

import re
from datetime import datetime
from typing import Dict, Optional

from app.models.event import LoginEvent, LoginResult, SourceType
from app.parsers.base import ParseError, normalize_ip

_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.(?P<fraction>[0-9]{1,6}))?(?:Z|[+-][0-9]{2}:[0-9]{2})?"
)
_USERNAME = re.compile(r"[A-Za-z0-9_.@-]+")
_FIELDS = ("username", "ip", "result")


def parse_web_line(line: str) -> Optional[LoginEvent]:
    """Parse ordered username/ip/result tokens; ignore non-LOGIN records."""
    raw = line.rstrip("\r\n")
    tokens = raw.split()
    if not tokens:
        return None
    if tokens[0] == "LOGIN":
        raise ParseError("web login event missing timestamp")
    if len(tokens) < 2 or tokens[1] != "LOGIN":
        return None
    if "\n" in raw or "\r" in raw:
        raise ParseError("web login event must occupy one line")
    fields: Dict[str, str] = {}
    for token in tokens[2:]:
        key, separator, value = token.partition("=")
        if not separator or key not in _FIELDS:
            raise ParseError("web login event has unexpected field")
        if key in fields:
            raise ParseError(f"web login event duplicate field: {key}")
        fields[key] = value
    for key in _FIELDS:
        if key not in fields:
            raise ParseError(f"web login event missing field: {key}")
    if tuple(fields) != _FIELDS:
        raise ParseError("web login fields must be ordered username, ip, result")
    if _USERNAME.fullmatch(fields["username"]) is None:
        raise ParseError("invalid web login username")
    if fields["result"] not in ("SUCCESS", "FAILURE"):
        raise ParseError("invalid web login result: expected SUCCESS or FAILURE")
    value = tokens[0]
    timestamp_match = _TIMESTAMP.fullmatch(value)
    if timestamp_match is None:
        raise ParseError("invalid web login timestamp")
    # Python 3.8 accepts only 3 or 6 fractional digits in fromisoformat.
    fraction = timestamp_match["fraction"]
    if fraction is not None:
        value = value.replace("." + fraction, "." + fraction.ljust(6, "0"), 1)
    # Python 3.8-3.10 do not accept Z in datetime.fromisoformat.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    elif len(value) >= 6 and value[-6] in ("+", "-"):
        if int(value[-5:-3]) > 23 or int(value[-2:]) > 59:
            raise ParseError("invalid web login timezone offset")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        raise ParseError("invalid web login timestamp") from None
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ParseError("web login timestamp must include timezone")
    return LoginEvent(
        timestamp=timestamp,
        source_type=SourceType.WEB,
        source_ip=normalize_ip(fields["ip"]),
        username=fields["username"],
        result=LoginResult(fields["result"].lower()),
        raw_log=raw,
    )
