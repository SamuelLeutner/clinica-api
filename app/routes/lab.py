from datetime import date, datetime, time, timedelta

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.database import get_session
from app.models.appointment import Appointment
from app.models.professional import HealthProfessional
from app.security.m2m import require_lab_scope

router = APIRouter(prefix="/lab", tags=["lab-integration"])


@router.get("/disponibilidade")
def disponibilidade(
    professional_id: int,
    on_date: date,
    client_id: str = Depends(require_lab_scope),  # noqa: ARG001 — token M2M validado, sub disponível se precisar de auditoria
    session: Session = Depends(get_session),
) -> dict:
    """O laboratório parceiro só enxerga horários ocupados/livres — nunca
    nome de paciente, notas clínicas ou qualquer outro dado de saúde. O
    response aqui é construído manualmente (não reusa AppointmentRead) para
    garantir que a superfície de dados exposta a este cliente M2M seja o
    mínimo possível, independentemente do que os response models da API
    humana venham a expor no futuro."""
    professional = session.get(HealthProfessional, professional_id)
    if professional is None:
        return {"professional_id": professional_id, "horarios_ocupados": []}

    start = datetime.combine(on_date, time.min)
    end = datetime.combine(on_date, time.max)
    occupied = session.exec(
        select(Appointment.scheduled_at).where(
            Appointment.professional_id == professional_id,
            Appointment.scheduled_at >= start,
            Appointment.scheduled_at <= end,
        )
    ).all()

    return {
        "professional_id": professional_id,
        "date": on_date.isoformat(),
        "horarios_ocupados": [t.isoformat() for t in occupied],
    }
