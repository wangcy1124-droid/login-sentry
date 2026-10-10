"""HTTP validation only; queries and database lifetime belong to services."""

from ipaddress import ip_address
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request

from app.models.alert import AlertStatus
from app.models.detection import RuleType
from app.services.query import QueryService

router = APIRouter(prefix='/api')


def service(request: Request) -> QueryService:
    return QueryService(request.app.state.database, request.app.state.clock)


@router.get('/alerts')
def alerts(status: Optional[AlertStatus] = None, rule_type: Optional[RuleType] = None,
           source_ip: Optional[str] = None, limit: int = Query(50, ge=1, le=100),
           offset: int = Query(0, ge=0, le=9223372036854775807), query: QueryService = Depends(service)):
    if source_ip is not None:
        try:
            source_ip = str(ip_address(source_ip))
        except ValueError:
            raise HTTPException(status_code=422, detail='source_ip must be a valid IPv4 or IPv6 address')
    return query.alerts(status, rule_type, source_ip, limit, offset)


@router.get('/alerts/{alert_id}')
def alert(alert_id: int = Path(..., ge=1, le=9223372036854775807), query: QueryService = Depends(service)):
    result = query.alert(alert_id)
    if result is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return result


@router.get('/events/{event_id}')
def event(event_id: int = Path(..., ge=1, le=9223372036854775807), query: QueryService = Depends(service)):
    result = query.event(event_id)
    if result is None:
        raise HTTPException(status_code=404, detail='Event not found')
    return result


@router.get('/statistics/summary')
def summary(query: QueryService = Depends(service)):
    return query.summary()


@router.get('/statistics/trend')
def trend(days: int = Query(7, ge=1, le=366), query: QueryService = Depends(service)):
    return query.trend(days)


@router.get('/statistics/sources')
def sources(limit: int = Query(10, ge=1, le=100), query: QueryService = Depends(service)):
    return query.sources(limit)


@router.get('/statistics/rules')
def rules(query: QueryService = Depends(service)):
    return query.rules()
