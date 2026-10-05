"""Evaluate persisted failures once; no alerts are stored."""

import argparse
from contextlib import closing

from app.config.loader import load_config
from app.db.database import connect_database, initialize_database
from app.services.detection import detect


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate persisted login events once")
    parser.add_argument("--database", default="data/login-sentry.sqlite3")
    parser.add_argument("--config", default="config/default.toml")
    args = parser.parse_args()
    config = load_config(args.config)
    with closing(connect_database(args.database)) as connection:
        initialize_database(connection)
        report = detect(connection, config)
    for match in report.matches:
        print("rule={} source_ip={} events={} distinct_usernames={} window_start={} window_end={} event_ids={}".format(
            match.rule_type.value, match.source_ip, match.event_count, match.distinct_usernames,
            match.window_start.isoformat(timespec="microseconds"), match.window_end.isoformat(timespec="microseconds"),
            ",".join(str(value) for value in match.event_ids)))
    print("matches={}".format(len(report.matches)))


if __name__ == "__main__":
    main()
