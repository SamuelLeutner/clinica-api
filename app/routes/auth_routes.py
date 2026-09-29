from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from app.database import get_session
from app.models.enums import UserRole
from app.models.schemas import MFAChallenge, MFAVerify, Token, UserCreate, UserRead
from app.models.user import User
from app.security.auth import (
    create_access_token,
    create_mfa_challenge,
    generate_mfa_secret,
    hash_password,
    verify_mfa_challenge,
    verify_password,
)
from app.security.m2m import issue_lab_token
from app.security.rate_limit import limiter
from app.config import get_settings

settings = get_settings()

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, session: Session = Depends(get_session)) -> User:
    existing = session.exec(select(User).where(User.username == payload.username)).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username já cadastrado")

    user = User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        professional_id=payload.professional_id,
        # MFA obrigatório para contas administrativas (Exercício 6).
        mfa_enabled=payload.role == UserRole.ADMIN,
        mfa_secret=generate_mfa_secret() if payload.role == UserRole.ADMIN else None,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.post("/token", response_model=Token | MFAChallenge)
@limiter.limit(settings.login_rate_limit)
def login(
    request: Request,  # noqa: ARG001 — exigido pelo slowapi para extrair o IP
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        # Mensagem genérica: não revela se foi o username ou a senha que errou.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Conta desativada")

    if user.mfa_enabled:
        challenge_id = create_mfa_challenge(user)
        return MFAChallenge(challenge_id=challenge_id)

    token = create_access_token(subject=user.username, role=user.role.value)
    return Token(access_token=token)


@router.post("/mfa/verify", response_model=Token)
def verify_mfa(payload: MFAVerify, session: Session = Depends(get_session)):
    user = verify_mfa_challenge(payload.challenge_id, payload.code, session)
    token = create_access_token(subject=user.username, role=user.role.value)
    return Token(access_token=token)


@router.post("/lab-token", response_model=Token)
@limiter.limit("10/minute")
def lab_token(
        request: Request,
        grant_type: str = Form(...),
        client_id: str = Form(...),
        client_secret: str = Form(...)
    ):  # noqa: ARG001
    """Client Credentials (RFC 6749 §4.4.2): credenciais no corpo, nunca na URL."""
    
    if grant_type != "client_credentials":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unsupported_grant_type")
    token = issue_lab_token(client_id, client_secret)
    return Token(access_token=token)