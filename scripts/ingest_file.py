"""Manual one-shot ingestion; install the project before running this script."""

import argparse
import re
from datetime import timedelta, timezone

from app.models.event import SourceType
from app.services.ingestion import ingest_file


def fixed_timezone(value: str) -> timezone:
    if value == "Z":
        return timezone.utc
    if re.fullmatch(r"[+-][0-9]{2}:[0-9]{2}", value) is None:
        raise argparse.ArgumentTypeError("timezone must be Z or +/-HH:MM")
    hours, minutes = int(value[1:3]), int(value[4:6])
    if hours > 23 or minutes > 59:
        raise argparse.ArgumentTypeError("timezone offset hours must be 0..23 and minutes 0..59")
    offset = timedelta(hours=hours, minutes=minutes)
    return timezone(-offset if value[0] == "-" else offset)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest complete lines once; resume from saved byte offsets")
    parser.add_argument("--type", choices=("ssh", "web"), required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--database", default="data/login-sentry.sqlite3")
    parser.add_argument("--year", type=int)
    parser.add_argument("--timezone", type=fixed_timezone)
    args = parser.parse_args()
    if args.type == "ssh" and (args.year is None or not 1 <= args.year <= 9999 or args.timezone is None):
        parser.error("SSH requires --year (1..9999) and --timezone")
    stats = ingest_file(args.path, args.database, SourceType(args.type), year=args.year, tzinfo=args.timezone)
    print("lines_read={} events_inserted={} ignored_lines={} parse_errors={}".format(
        stats.lines_read, stats.events_inserted, stats.ignored_lines, stats.parse_errors))


if __name__ == "__main__":
    main()
