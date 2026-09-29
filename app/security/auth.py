"""
Autenticação (Exercício 6).

- Senhas: hash bcrypt via passlib. Nunca há texto plano em lugar nenhum
  além do momento em que a requisição HTTP chega (e mesmo assim, apenas em
  memória, nunca logado).
- Sessões: JWT assinado (HS256) com expiração curta (access_token_expire_minutes,
  padrão 15 min), lido via OAuth2PasswordBearer.
- MFA: simulado com TOTP real (pyotp) — mesmo algoritmo usado por apps como
  Google Authenticator. "Simulado" aqui significa que não há um app externo
  de fato instalado durante o teste automatizado: o teste gera o código
  válido chamando pyotp diretamente com o secret da conta, exatamente como
  um autenticador real faria a cada 30s.
"""
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi import Cookie, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Session, select

from app.config import get_settings
from app.database import get_session
from app.models.user import User

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)

# Armazenamento de desafios MFA pendentes. Em produção isso seria Redis
# com TTL nativo; aqui usamos um dict com expiração verificada manualmente
# — suficiente para o escopo do Assessment, e documentado como tal.
_mfa_challenges: dict[str, dict] = {}


# --------------------------------------------------------------------------
# Senhas
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# --------------------------------------------------------------------------
# JWT
# --------------------------------------------------------------------------
def create_access_token(*, subject: str, role: str, extra_claims: dict | None = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": expire,
        "jti": str(uuid.uuid4()),  # suporta futura revogação/blacklist por jti
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_current_user_from_cookie(
    access_token: str | None = Cookie(default=None),
    session: Session = Depends(get_session),
) -> User:
    """Variante de get_current_user para o cliente HTML da recepção
    (Exercício 2). O JWT é o mesmo formato/segredo, mas é transportado em
    cookie httponly em vez de header Authorization, porque o cliente é um
    navegador renderizando páginas server-side, não um consumidor de API
    JSON. A rota FastAPI injeta o cookie explicitamente (veja
    app/routes/reception.py) para manter esta função testável sem
    depender do objeto Request completo."""
    if access_token is None:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/reception/login"})
    payload = decode_access_token(access_token)
    username = payload.get("sub")
    user = session.exec(select(User).where(User.username == username)).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/reception/login"})
    return user


def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    """Dependency central de autenticação. Toda rota protegida da API
    humana depende disso — é o único lugar que decodifica o JWT e busca o
    usuário, evitando lógica de autenticação duplicada entre módulos."""
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Não autenticado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(token)
    if payload.get("scope") is not None:
        # Qualquer token que carregue `scope` é um token M2M (ver
        # app/security/m2m.py) — tokens de usuário humano nunca têm esse
        # claim. Bloqueado explicitamente antes de qualquer lookup de
        # usuário, para não depender de um "sub" que nem existe na tabela
        # User dar erro genérico de "usuário inválido".
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token M2M não pode acessar rotas de usuário")

    username = payload.get("sub")
    user = session.exec(select(User).where(User.username == username)).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário inválido ou inativo")
    return user


# --------------------------------------------------------------------------
# MFA simulado (TOTP)
# --------------------------------------------------------------------------
def generate_mfa_secret() -> str:
    return pyotp.random_base32()


def create_mfa_challenge(user: User) -> str:
    challenge_id = secrets.token_urlsafe(16)
    _mfa_challenges[challenge_id] = {
        "username": user.username,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=settings.mfa_challenge_expire_minutes),
    }
    return challenge_id


def verify_mfa_challenge(challenge_id: str, code: str, session: Session) -> User:
    challenge = _mfa_challenges.get(challenge_id)
    if challenge is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Desafio MFA inválido")
    if datetime.now(timezone.utc) > challenge["expires_at"]:
        del _mfa_challenges[challenge_id]
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Desafio MFA expirado")

    user = session.exec(select(User).where(User.username == challenge["username"])).first()
    if user is None or not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Conta sem MFA configurado")

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código MFA incorreto")

    del _mfa_challenges[challenge_id]
    return user
