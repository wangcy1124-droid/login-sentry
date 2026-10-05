"""Detect and persist alerts once; no notification delivery."""

import argparse
from contextlib import closing
from dataclasses import asdict

from app.config.loader import load_config
from app.db.database import connect_database, initialize_database
from app.services.alerting import process_alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="Persist and aggregate login alerts once")
    parser.add_argument('--database', default='data/login-sentry.sqlite3')
    parser.add_argument('--config', default='config/default.toml')
    args = parser.parse_args()
    config = load_config(args.config)
    with closing(connect_database(args.database)) as connection:
        initialize_database(connection)
        stats = process_alerts(connection, config)
    print(' '.join('{}={}'.format(key, value) for key, value in asdict(stats).items()))


if __name__ == '__main__':
    main()
