from datetime import date, datetime, timezone

from sqlmodel import Field, SQLModel


class Patient(SQLModel, table=True):
    """Dado de paciente — categoria sensível sob a LGPD (art. 5º, II,
    dado de saúde é considerado dado sensível). `created_by_user_id` é
    campo de auditoria interna e nunca é exposto na API (Exercício 2)."""

    id: int | None = Field(default=None, primary_key=True)
    full_name: str = Field(max_length=120)
    cpf: str = Field(max_length=11, index=True, unique=True)  # somente dígitos, validado na entrada
    birth_date: date
    phone: str = Field(max_length=20)
    email: str = Field(max_length=120)

    # Auditoria interna.
    created_by_user_id: int | None = Field(default=None, foreign_key="user.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
