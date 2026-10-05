"""Persist a human review decision without deleting history."""

import argparse
from contextlib import closing

from app.db.database import connect_database, initialize_database
from app.models.alert import AlertStatus
from app.services.alerting import review_alert


def main() -> None:
    parser = argparse.ArgumentParser(description="Review a persisted alert")
    parser.add_argument('--database', default='data/login-sentry.sqlite3')
    parser.add_argument('--alert-id', type=int, required=True)
    parser.add_argument('--status', choices=[status.value for status in AlertStatus], required=True)
    parser.add_argument('--note')
    args = parser.parse_args()
    with closing(connect_database(args.database)) as connection:
        initialize_database(connection)
        alert = review_alert(connection, args.alert_id, AlertStatus(args.status), args.note)
    print('alert_id={} status={}'.format(alert.id, alert.status.value))


if __name__ == '__main__':
    main()
