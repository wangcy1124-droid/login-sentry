"""One-shot parser selection and database lifecycle."""

from contextlib import closing
from datetime import tzinfo as Timezone
from functools import partial
from pathlib import Path
from typing import Optional, Union

from app.collectors.file_collector import CollectionStats, collect_file
from app.db.database import connect_database, initialize_database
from app.models.event import SourceType
from app.parsers.ssh import parse_ssh_line
from app.parsers.web import parse_web_line


def ingest_file(
    path: Union[str, Path], database: Union[str, Path], source_type: SourceType,
    *, year: Optional[int] = None, tzinfo: Optional[Timezone] = None,
) -> CollectionStats:
    if source_type == SourceType.SSH:
        if type(year) is not int or not 1 <= year <= 9999 or not isinstance(tzinfo, Timezone):
            raise ValueError("SSH ingestion requires year 1..9999 and explicit timezone")
        parser = partial(parse_ssh_line, year=year, tzinfo=tzinfo)
    elif source_type == SourceType.WEB:
        parser = parse_web_line
    else:
        raise ValueError("source_type must be ssh or web")
    with closing(connect_database(database)) as connection:
        initialize_database(connection)
        return collect_file(path, parser, connection)
