from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.db.database import connect_database, initialize_database
from app.db.repositories import LoginEventRepository
from app.db.alert_repositories import AlertRepository
from app.models.event import LoginEvent, LoginResult, SourceType
from app.models.detection import DetectionMatch, RuleType
from app.models.alert import AlertStatus
from app.services.alerting import review_alert

NOW = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)


@pytest.fixture
def setup(tmp_path):
    path = tmp_path / 'api.sqlite3'
    app = create_app(str(path), clock=lambda: NOW)
    with TestClient(app) as client:
        yield client, path


def seed(path):
    with closing(connect_database(path)) as conn:
        initialize_database(conn)
        repo = AlertRepository(conn)
        # Deliberately scramble dates; IDs break identical-date ties.
        for days, rule, ip, status in [
            (0, RuleType.FAILURE_BURST, '192.0.2.10', AlertStatus.OPEN),
            (1, RuleType.MULTI_ACCOUNT, '2001:db8::10', AlertStatus.CONFIRMED),
            (0, RuleType.MULTI_ACCOUNT, '192.0.2.10', AlertStatus.FALSE_POSITIVE),
            (7, RuleType.FAILURE_BURST, '192.0.2.20', AlertStatus.RESOLVED),
        ]:
            timestamp = NOW.replace(hour=0) - timedelta(days=days)
            raw = '<script>alert("synthetic")</script>'
            with conn:
                eid = LoginEventRepository(conn).insert(LoginEvent(timestamp, SourceType.WEB, ip, 'alice', LoginResult.FAILURE, raw))
                match = DetectionMatch(rule, ip, timestamp, timestamp, (eid,), 1, 1)
                aid = repo.create(match, NOW)
                repo.add_links(aid, match, NOW)
            if status != AlertStatus.OPEN:
                review_alert(conn, aid, status)


def test_empty_and_dashboard(setup):
    client, path = setup
    assert client.get('/api/alerts').json() == {'items': [], 'total': 0}
    assert client.get('/api/statistics/summary').json() == dict(total_alerts=0, open_alerts=0, confirmed_alerts=0, false_positive_alerts=0, resolved_alerts=0)
    for name in ('sources', 'rules'):
        assert client.get('/api/statistics/'+name).json() == []
    trend = client.get('/api/statistics/trend').json()
    assert len(trend) == 7 and all(x['count'] == 0 for x in trend)
    assert trend[0]['date'] == '2026-10-05' and trend[-1]['date'] == '2026-10-11'
    response = client.get('/')
    assert response.status_code == 200
    assert 'echarts@5.6.0' in response.text and 'Total Alerts' in response.text
    for asset in ('dashboard.js', 'dashboard.css'):
        assert client.get('/static/'+asset).status_code == 200
    assert client.get('/api/health').json() == {'status':'ok','service':'login-sentry'}


def test_pagination_and_combined_filters(setup):
    client, path = setup; seed(path)
    result = client.get('/api/alerts?limit=2&offset=1').json()
    assert result['total'] == 4 and [x['id'] for x in result['items']] == [1,2]
    assert [x['id'] for x in client.get('/api/alerts').json()['items']] == [3,1,2,4]
    assert client.get('/api/alerts?offset=99').json() == {'items':[], 'total':4}
    for params, ids in [({'status':'confirmed'},[2]), ({'rule_type':'failure_burst'},[1,4]),
                        ({'source_ip':'192.0.2.10'},[3,1]),
                        ({'source_ip':'2001:0db8::10'},[2]),
                        ({'status':'open','rule_type':'failure_burst','source_ip':'192.0.2.10'},[1])]:
        data = client.get('/api/alerts',params=params).json()
        assert data['total'] == len(ids) and [x['id'] for x in data['items']] == ids


@pytest.mark.parametrize('url', ['/api/alerts?status=bad', '/api/alerts?rule_type=bad',
    '/api/alerts?source_ip=999.1.1.1', "/api/alerts?source_ip=' OR 1=1--", '/api/alerts?limit=0',
    '/api/alerts?limit=101', '/api/alerts?offset=-1', '/api/statistics/trend?days=0',
    '/api/statistics/trend?days=367', '/api/statistics/sources?limit=101'])
def test_invalid_input(setup, url):
    assert setup[0].get(url).status_code == 422


def test_details_and_missing(setup):
    client,path=setup; seed(path)
    response=client.get('/api/alerts/1')
    assert response.status_code==200
    data=response.json()
    assert data['alert']['fingerprint']=='failure_burst|192.0.2.10'
    event=data['events'][0]
    assert event['id']==1 and event['timestamp']=='2026-10-11T00:00:00+00:00'
    assert event['source_type']=='web' and event['result']=='failure'
    assert event['raw_log']=='<script>alert("synthetic")</script>'
    assert client.get('/api/events/1').json()==event
    for url in ('/api/events/999','/api/alerts/999'):
        assert client.get(url).status_code==404


def test_statistics_and_read_only(setup):
    client,path=setup; seed(path)
    with closing(connect_database(path)) as c: before=list(c.iterdump())
    assert client.get('/api/statistics/summary').json()==dict(total_alerts=4,open_alerts=1,confirmed_alerts=1,false_positive_alerts=1,resolved_alerts=1)
    trend=client.get('/api/statistics/trend').json()
    assert trend[-2:]==[{'date':'2026-10-10','count':1},{'date':'2026-10-11','count':2}]
    assert sum(x['count'] for x in trend)==3
    assert sum(x['count'] for x in client.get('/api/statistics/trend?days=8').json())==4
    assert client.get('/api/statistics/sources?limit=1').json()==[{'source_ip':'192.0.2.10','count':2}]
    assert client.get('/api/statistics/rules').json()==[{'rule_type':'failure_burst','count':2},{'rule_type':'multi_account','count':2}]
    client.get('/api/alerts'); client.get('/api/alerts/1'); client.get('/api/events/1')
    with closing(connect_database(path)) as c: assert list(c.iterdump())==before


def test_connections_isolated_per_app(tmp_path):
    first,second=tmp_path/'first.sqlite3',tmp_path/'second.sqlite3'
    seed(first)
    with TestClient(create_app(str(first))) as a, TestClient(create_app(str(second))) as b:
        assert a.get('/api/alerts').json()['total']==4
        assert b.get('/api/alerts').json()['total']==0


@pytest.mark.parametrize('url', ['/api/alerts?offset=999999999999999999999',
                                '/api/events/999999999999999999999', '/api/alerts/0'])
def test_sqlite_integer_bounds(setup, url):
    assert setup[0].get(url).status_code == 422


def test_trend_utc_midnight_boundaries(tmp_path):
    path = tmp_path/'boundaries.sqlite3'
    end = datetime(2026,10,12,tzinfo=timezone.utc)
    start = end - timedelta(days=7)
    with closing(connect_database(path)) as conn:
        initialize_database(conn)
        repo=AlertRepository(conn)
        for timestamp in (start-timedelta(microseconds=1), start, end-timedelta(microseconds=1), end):
            with conn:
                event_id=LoginEventRepository(conn).insert(LoginEvent(timestamp,SourceType.WEB,'192.0.2.10','alice',LoginResult.FAILURE,'synthetic'))
                repo.create(DetectionMatch(RuleType.FAILURE_BURST,'192.0.2.10',timestamp,timestamp,(event_id,),1,1),NOW)
    # This local date is Oct 12, but the UTC date remains Oct 11.
    clock=lambda: datetime(2026,10,12,1,tzinfo=timezone(timedelta(hours=8)))
    with TestClient(create_app(str(path),clock=clock)) as client:
        trend=client.get('/api/statistics/trend').json()
        assert trend[0]=={'date':'2026-10-05','count':1}
        assert trend[-1]=={'date':'2026-10-11','count':1}
        assert sum(item['count'] for item in trend)==2
