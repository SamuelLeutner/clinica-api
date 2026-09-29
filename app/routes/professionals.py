from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from app.database import get_session
from app.models.enums import UserRole
from app.models.professional import HealthProfessional
from app.models.schemas import ProfessionalCreate, ProfessionalRead
from app.models.user import User
from app.security.auth import get_current_user
from app.security.permissions import require_roles

router = APIRouter(prefix="/professionals", tags=["professionals"])


@router.post("", response_model=ProfessionalRead, status_code=status.HTTP_201_CREATED)
def create_professional(
    payload: ProfessionalCreate,
    current_user: User = Depends(require_roles(UserRole.ADMIN)),  # noqa: ARG001
    session: Session = Depends(get_session),
) -> HealthProfessional:
    existing = session.exec(
        select(HealthProfessional).where(HealthProfessional.license_number == payload.license_number)
    ).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="license_number já cadastrado")

    professional = HealthProfessional(**payload.model_dump())
    session.add(professional)
    session.commit()
    session.refresh(professional)
    return professional


@router.get("", response_model=list[ProfessionalRead])
def list_professionals(
    current_user: User = Depends(get_current_user),  # noqa: ARG001
    session: Session = Depends(get_session),
) -> list[HealthProfessional]:
    return list(session.exec(select(HealthProfessional)))
