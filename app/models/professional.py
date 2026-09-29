from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


class HealthProfessional(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    full_name: str = Field(max_length=120)
    specialty: str = Field(max_length=80)
    license_number: str = Field(max_length=20, unique=True)  # CRM/CRO/etc.

    # Auditoria interna.
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
