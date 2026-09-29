from dataclasses import dataclass
from datetime import date, datetime, time

from fastapi import APIRouter, Cookie, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from app.config import settings
from app.database import get_session
from app.models.appointment import Appointment
from app.models.enums import UserRole
from app.models.patient import Patient
from app.models.professional import HealthProfessional
from app.models.user import User
from app.security.auth import create_access_token, get_current_user_from_cookie, verify_password
from app.security.csrf import CSRF_COOKIE_NAME, generate_csrf_token, verify_csrf_token

router = APIRouter(prefix="/reception", tags=["reception-html"])
templates = Jinja2Templates(directory="app/templates")  # autoescape ligado por padrão para .html


@dataclass
class AgendaRow:
    scheduled_at: datetime
    status: object
    notes: str
    patient_name: str
    professional_name: str


@router.get("/login")
def login_form(request: Request):
    csrf_token = generate_csrf_token()
    response = templates.TemplateResponse(request=request, name="login.html", context={"csrf_token": csrf_token})
    response.set_cookie(key=CSRF_COOKIE_NAME, value=csrf_token, httponly=True, samesite="lax", max_age=10 * 60)
    return response


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    session: Session = Depends(get_session),
):
    verify_csrf_token(csrf_cookie, csrf_token)

    user = session.exec(select(User).where(User.username == username)).first()
    if user is None or not verify_password(password, user.hashed_password) or not user.is_active:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Usuário ou senha inválidos", "csrf_token": csrf_token},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    if user.role not in (UserRole.RECEPCIONISTA, UserRole.ADMIN):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Este painel é restrito à recepção", "csrf_token": csrf_token},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    token = create_access_token(subject=user.username, role=user.role.value)
    response = RedirectResponse("/reception/agenda", status_code=status.HTTP_303_SEE_OTHER)
    # httponly: o cookie não é acessível via JavaScript no browser, o que
    # reduz o impacto de um XSS eventual (defesa em profundidade além do
    # auto-escape do Jinja2). secure=True exige HTTPS — desligado apenas
    # em ambiente de teste local via variável de ambiente, se necessário.
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=15 * 60,
    )
    response.delete_cookie(CSRF_COOKIE_NAME)  # token de uso único: não sobrevive ao login bem-sucedido
    return response


@router.get("/agenda")
def agenda(
    request: Request,
    current_user: User = Depends(get_current_user_from_cookie),
    session: Session = Depends(get_session),
):
    if current_user.role != UserRole.RECEPCIONISTA and current_user.role != UserRole.ADMIN:
        return RedirectResponse("/reception/login", status_code=status.HTTP_303_SEE_OTHER)

    today = date.today()
    start = datetime.combine(today, time.min)
    end = datetime.combine(today, time.max)

    rows = session.exec(
        select(Appointment, Patient, HealthProfessional)
        .join(Patient, Patient.id == Appointment.patient_id)
        .join(HealthProfessional, HealthProfessional.id == Appointment.professional_id)
        .where(Appointment.scheduled_at >= start, Appointment.scheduled_at <= end)
        .order_by(Appointment.scheduled_at)
    ).all()

    agenda_rows = [
        AgendaRow(
            scheduled_at=appt.scheduled_at,
            status=appt.status,
            notes=appt.notes,
            patient_name=patient.full_name,
            professional_name=professional.full_name,
        )
        for appt, patient, professional in rows
    ]

    return templates.TemplateResponse(
        request=request,
        name="agenda.html",
        context={"today": today.isoformat(), "appointments": agenda_rows},
    )
