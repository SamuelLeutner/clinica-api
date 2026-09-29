from datetime import datetime, timezone

from sqlmodel import Field, SQLModel

from app.models.enums import AppointmentStatus


class Appointment(SQLModel, table=True):
    """Recurso central da API. `created_by_user_id` e `updated_at` são
    campos de auditoria interna — vazá-los facilitaria a identificação de
    qual funcionário tocou em qual registro de paciente, então ficam de
    fora de todo response_model (Exercício 2)."""

    id: int | None = Field(default=None, primary_key=True)
    patient_id: int = Field(foreign_key="patient.id", index=True)
    professional_id: int = Field(foreign_key="healthprofessional.id", index=True)
    scheduled_at: datetime
    status: AppointmentStatus = Field(default=AppointmentStatus.AGENDADA)
    notes: str = Field(default="", max_length=1000)

    # Auditoria interna — nunca exposta na API.
    created_by_user_id: int | None = Field(default=None, foreign_key="user.id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
