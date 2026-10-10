"""Request-scoped connection lifetime, serialization and UTC statistics semantics."""

from contextlib import contextmanager, closing
from dataclasses import asdict
from datetime import timedelta, timezone

from app.db.database import connect_database, initialize_database
from app.db.alert_repositories import AlertRepository
from app.db.query_repositories import QueryRepository
from app.db.repositories import LoginEventRepository, utc_now, utc_text


def event_document(event_id, event):
    return dict(id=event_id, timestamp=event.timestamp, source_type=event.source_type,
                source_ip=event.source_ip, username=event.username, result=event.result, raw_log=event.raw_log)


class QueryService:
    def __init__(self, database, clock=utc_now):
        self.database = database
        self.clock = clock

    @contextmanager
    def connection(self):
        # Open/use/close on the same worker thread. Empty databases gain the existing schema.
        with closing(connect_database(self.database)) as connection:
            initialize_database(connection)
            connection.execute('BEGIN')
            try:
                yield connection
            finally:
                connection.rollback()

    def alerts(self, status=None, rule_type=None, source_ip=None, limit=50, offset=0):
        with self.connection() as connection:
            items, total = QueryRepository(connection).alerts(
                status.value if status else None, rule_type.value if rule_type else None,
                source_ip, limit, offset)
            return dict(items=[asdict(item) for item in items], total=total)

    def alert(self, alert_id):
        with self.connection() as connection:
            repository = AlertRepository(connection)
            alert = repository.get_by_id(alert_id)
            if alert is None:
                return None
            return dict(alert=asdict(alert), events=[event_document(record.id, record.event)
                        for record in repository.list_events(alert_id)])

    def event(self, event_id):
        with self.connection() as connection:
            event = LoginEventRepository(connection).get_by_id(event_id)
            return None if event is None else event_document(event_id, event)

    def summary(self):
        with self.connection() as connection:
            return QueryRepository(connection).summary()

    def trend(self, days):
        now = self.clock()
        utc_text(now)  # Reject naive injected clocks.
        end = now.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        start = end - timedelta(days=days)
        with self.connection() as connection:
            counts = QueryRepository(connection).trend(start, end)
        dates = [(start + timedelta(days=i)).date().isoformat() for i in range(days)]
        return [dict(date=date, count=counts.get(date, 0)) for date in dates]

    def sources(self, limit):
        with self.connection() as connection:
            return QueryRepository(connection).sources(limit)

    def rules(self):
        with self.connection() as connection:
            return QueryRepository(connection).rules()
