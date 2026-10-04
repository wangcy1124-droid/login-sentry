"""Parse traditional syslog OpenSSH login results with explicit time context."""

import re
from datetime import datetime, tzinfo as Timezone
from typing import Optional

from app.models.event import LoginEvent, LoginResult, SourceType
from app.parsers.base import ParseError, normalize_ip

# The loose envelope identifies target messages even if PID/prefix is damaged.
_ENVELOPE = re.compile(r"(?:^|[ \t])sshd(?=[\[: \t])(?:\[[^\s:]*)?[ \t]*:?[ \t]*(?P<message>[^\r\n]*)")
_TARGET = re.compile(r"(?:Accepted[ \t]+(?:password|publickey)|Failed[ \t]+password)(?:[ \t]|$)")
_PREFIX = re.compile(
    r"(?P<month>[A-Za-z]{3})[ \t]+(?P<day>[0-9]{1,2})[ \t]+"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})[ \t]+"
    r"[^\s]+[ \t]+sshd\[[0-9]+\]:[ \t]*(?P<message>[^\r\n]*)"
)
_ACCEPTED = re.compile(
    r"Accepted[ \t]+(?P<method>password|publickey)[ \t]+for[ \t]+"
    r"(?P<username>[^\s]+)[ \t]+from[ \t]+(?P<ip>[^\s]+)[ \t]+"
    r"port[ \t]+(?P<port>[0-9]{1,5})[ \t]+ssh2(?P<suffix>[^\r\n]*)"
)
_FAILED = re.compile(
    r"Failed[ \t]+password[ \t]+for[ \t]+(?:invalid[ \t]+user[ \t]+)?"
    r"(?P<username>[^\s]+)[ \t]+from[ \t]+(?P<ip>[^\s]+)[ \t]+"
    r"port[ \t]+(?P<port>[0-9]{1,5})[ \t]+ssh2[ \t]*"
)
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def parse_ssh_line(line: str, *, year: int, tzinfo: Timezone) -> Optional[LoginEvent]:
    """Return None for unrelated messages; raise ParseError for damaged targets.

    No year rollover inference is performed. Publickey metadata after ssh2 is
    retained in raw_log but is not interpreted.
    """
    raw = line.rstrip("\r\n")
    envelope = _ENVELOPE.search(raw)
    if envelope is None or _TARGET.match(envelope["message"]) is None:
        return None
    prefix = _PREFIX.fullmatch(raw)
    if prefix is None:
        raise ParseError("invalid SSH syslog prefix")
    message = prefix["message"]
    accepted = message.startswith("Accepted")
    match = (_ACCEPTED if accepted else _FAILED).fullmatch(message)
    if match is None:
        raise ParseError("invalid SSH login fields")
    if accepted:
        suffix = match["suffix"]
        if suffix and not suffix.startswith((" ", "\t", ": ")):
            raise ParseError("invalid SSH protocol suffix")
        if match["method"] == "password" and suffix.strip():
            raise ParseError("unexpected SSH password login fields")
    if not 1 <= int(match["port"]) <= 65535:
        raise ParseError("invalid SSH source port")
    try:
        timestamp = datetime(
            year, _MONTHS.index(prefix["month"]) + 1, int(prefix["day"]),
            int(prefix["hour"]), int(prefix["minute"]), int(prefix["second"]),
            tzinfo=tzinfo,
        )
    except (ValueError, TypeError):
        raise ParseError("invalid SSH timestamp or year/timezone context") from None
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ParseError("SSH timestamp context must include timezone")
    return LoginEvent(
        timestamp=timestamp,
        source_type=SourceType.SSH,
        source_ip=normalize_ip(match["ip"]),
        username=match["username"],
        result=LoginResult.SUCCESS if accepted else LoginResult.FAILURE,
        raw_log=raw,
    )
