from datetime import UTC, datetime


def utc_now() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    """Attach UTC only for storage known to have been normalised before writing.

    SQLite DateTime drops offsets. Legacy authorisation windows must additionally
    pass timestamps_verified; this helper cannot recover a lost source offset.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
