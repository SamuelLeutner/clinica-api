from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from app.database import get_session
from app.models.enums import UserRole
from app.models.patient import Patient
from app.models.schemas import PatientCreate, PatientRead, PatientReadDetailed
from app.models.user import User
from app.security.auth import get_current_user
from app.security.permissions import require_roles

router = APIRouter(prefix="/patients", tags=["patients"])


@router.post("", response_model=PatientRead, status_code=status.HTTP_201_CREATED)
def create_patient(
    payload: PatientCreate,
    current_user: User = Depends(require_roles(UserRole.RECEPCIONISTA, UserRole.ADMIN)),
    session: Session = Depends(get_session),
) -> Patient:
    existing = session.exec(select(Patient).where(Patient.cpf == payload.cpf)).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Paciente com este CPF já cadastrado")

    patient = Patient(**payload.model_dump(), created_by_user_id=current_user.id)
    session.add(patient)
    session.commit()
    session.refresh(patient)
    return patient


@router.get("", response_model=list[PatientRead])
def list_patients(
    current_user: User = Depends(get_current_user),  # noqa: ARG001 — exige apenas autenticação
    session: Session = Depends(get_session),
) -> list[Patient]:
    return list(session.exec(select(Patient)))


@router.get("/{patient_id}", response_model=PatientReadDetailed)
def get_patient(
    patient_id: int,
    current_user: User = Depends(require_roles(UserRole.RECEPCIONISTA, UserRole.PROFISSIONAL, UserRole.ADMIN)),  # noqa: ARG001
    session: Session = Depends(get_session),
) -> Patient:
    patient = session.get(Patient, patient_id)
    if patient is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Paciente não encontrado")
    return patient
