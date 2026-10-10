"""Read-only query SQL; all external values are bound parameters."""

from app.db.alert_repositories import AlertRepository
from app.db.repositories import utc_text


class QueryRepository:
    def __init__(self, connection):
        self.connection = connection

    def alerts(self, status=None, rule_type=None, source_ip=None, limit=50, offset=0):
        parameters = (status, status, rule_type, rule_type, source_ip, source_ip)
        total = self.connection.execute(
            'SELECT COUNT(*) FROM alerts WHERE (? IS NULL OR status = ?) '
            'AND (? IS NULL OR rule_type = ?) AND (? IS NULL OR source_ip = ?)', parameters).fetchone()[0]
        rows = self.connection.execute(
            'SELECT * FROM alerts WHERE (? IS NULL OR status = ?) '
            'AND (? IS NULL OR rule_type = ?) AND (? IS NULL OR source_ip = ?) '
            'ORDER BY last_seen_utc DESC, id DESC LIMIT ? OFFSET ?', parameters + (limit, offset))
        return [AlertRepository._alert(row) for row in rows], total

    def summary(self):
        counts = dict(self.connection.execute('SELECT status, COUNT(*) FROM alerts GROUP BY status'))
        return dict(total_alerts=sum(counts.values()), open_alerts=counts.get('open', 0),
                    confirmed_alerts=counts.get('confirmed', 0),
                    false_positive_alerts=counts.get('false_positive', 0), resolved_alerts=counts.get('resolved', 0))

    def trend(self, start, end):
        return dict(self.connection.execute(
            'SELECT substr(first_seen_utc, 1, 10), COUNT(*) FROM alerts '
            'WHERE first_seen_utc >= ? AND first_seen_utc < ? '
            'GROUP BY substr(first_seen_utc, 1, 10) ORDER BY substr(first_seen_utc, 1, 10)',
            (utc_text(start), utc_text(end))))

    def sources(self, limit):
        return [dict(row) for row in self.connection.execute(
            'SELECT source_ip, COUNT(*) AS count FROM alerts GROUP BY source_ip '
            'ORDER BY count DESC, source_ip ASC LIMIT ?', (limit,))]

    def rules(self):
        return [dict(row) for row in self.connection.execute(
            'SELECT rule_type, COUNT(*) AS count FROM alerts GROUP BY rule_type ORDER BY rule_type')]
