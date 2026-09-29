from datetime import date, datetime, time

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from app.database import get_session
from app.models.appointment import Appointment
from app.models.enums import AppointmentStatus, UserRole
from app.models.schemas import AppointmentCreate, AppointmentRead, AppointmentUpdate
from app.models.user import User
from app.security.auth import get_current_user
from app.security.permissions import require_roles, verify_appointment_ownership

router = APIRouter(prefix="/appointments", tags=["appointments"])


@router.post("", response_model=AppointmentRead, status_code=status.HTTP_201_CREATED)
def create_appointment(
    payload: AppointmentCreate,
    current_user: User = Depends(require_roles(UserRole.PROFISSIONAL, UserRole.ADMIN)),
    session: Session = Depends(get_session),
) -> Appointment:
    professional_id = payload.professional_id
    if current_user.role == UserRole.PROFISSIONAL:
        # Um profissional só pode criar consultas em seu próprio nome —
        # mesmo que tente enviar outro professional_id no corpo, ele é
        # ignorado. Isso evita um mass-assignment que permitiria a um
        # profissional agendar (e depois modificar) consultas de colegas.
        professional_id = current_user.professional_id

    appointment = Appointment(
        patient_id=payload.patient_id,
        professional_id=professional_id,
        scheduled_at=payload.scheduled_at,
        notes=payload.notes,
        created_by_user_id=current_user.id,
    )
    session.add(appointment)
    session.commit()
    session.refresh(appointment)
    return appointment


@router.get("", response_model=list[AppointmentRead])
def list_appointments(
    on_date: date | None = None,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[Appointment]:
    query = select(Appointment)

    if current_user.role == UserRole.PROFISSIONAL:
        # Sem ownership check aqui, um profissional veria a agenda de
        # todos os colegas — a mesma classe de falha do Exercício 8,
        # só que na listagem em vez de no detalhe.
        query = query.where(Appointment.professional_id == current_user.professional_id)
    elif current_user.role not in (UserRole.RECEPCIONISTA, UserRole.ADMIN):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Papel sem permissão de listagem")

    if on_date is not None:
        start = datetime.combine(on_date, time.min)
        end = datetime.combine(on_date, time.max)
        query = query.where(Appointment.scheduled_at >= start, Appointment.scheduled_at <= end)

    return list(session.exec(query))


@router.get("/{appointment_id}", response_model=AppointmentRead)
def get_appointment(
    appointment: Appointment = Depends(verify_appointment_ownership),
) -> Appointment:
    return appointment


@router.patch("/{appointment_id}", response_model=AppointmentRead)
def update_appointment(
    payload: AppointmentUpdate,
    appointment: Appointment = Depends(verify_appointment_ownership),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> Appointment:
    if current_user.role not in (UserRole.PROFISSIONAL, UserRole.ADMIN):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Papel sem permissão de edição")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(appointment, field, value)
    appointment.updated_at = datetime.utcnow()

    session.add(appointment)
    session.commit()
    session.refresh(appointment)
    return appointment


@router.patch("/{appointment_id}/status", response_model=AppointmentRead)
def update_appointment_status(
    new_status: AppointmentStatus,
    appointment: Appointment = Depends(verify_appointment_ownership),
    current_user: User = Depends(require_roles(UserRole.RECEPCIONISTA, UserRole.PROFISSIONAL, UserRole.ADMIN)),
    session: Session = Depends(get_session),
) -> Appointment:
    """Endpoint restrito só ao campo status — é o que a recepção usa para
    confirmar/cancelar, sem precisar (nem poder) tocar em `notes` clínicas."""
    appointment.status = new_status
    appointment.updated_at = datetime.utcnow()
    session.add(appointment)
    session.commit()
    session.refresh(appointment)
    return appointment


@router.delete("/{appointment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_appointment(
    appointment: Appointment = Depends(verify_appointment_ownership),
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
    session: Session = Depends(get_session),
) -> None:
    session.delete(appointment)
    session.commit()
