from datetime import date, timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from app.database import get_session
from app.main import app
from app.models.user import User


@pytest.fixture(name="session")
def session_fixture():
    """Banco SQLite em memória, isolado por teste — sem tocar no
    clinica.db de desenvolvimento e sem estado vazando entre testes."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    from app.security.rate_limit import limiter

    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    limiter.reset()  # cada teste começa com o contador de rate limit zerado
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def today_iso() -> str:
    return date.today().isoformat()


@pytest.fixture
def tomorrow_iso() -> str:
    return (date.today() + timedelta(days=1)).isoformat()


def register_and_login(
    client: TestClient,
    session: Session,
    *,
    username: str,
    password: str,
    role: str,
    professional_id: int | None = None,
) -> str:
    """Helper: cadastra um usuário e devolve um Bearer token pronto para
    uso. Passa por MFA automaticamente se a conta exigir (admin)."""
    payload = {"username": username, "password": password, "role": role}
    if professional_id is not None:
        payload["professional_id"] = professional_id
    r = client.post("/auth/register", json=payload)
    assert r.status_code == 201, r.text

    r = client.post("/auth/token", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    body = r.json()

    if body.get("mfa_required"):
        from sqlmodel import select

        # Busca o secret diretamente na sessão de teste (equivalente a ler
        # o QR code que o app real mostraria uma única vez no cadastro).
        user_row = session.exec(select(User).where(User.username == username)).first()
        code = pyotp.TOTP(user_row.mfa_secret).now()
        r = client.post("/auth/mfa/verify", json={"challenge_id": body["challenge_id"], "code": code})
        assert r.status_code == 200, r.text
        body = r.json()

    return body["access_token"]


def reception_login(
    client: TestClient,
    username: str,
    password: str,
    follow_redirects: bool = True,
):
    """Faz login no painel HTML da recepção usando o fluxo real de CSRF
    double-submit-cookie da aplicação."""
    r = client.get("/reception/login")
    assert r.status_code == 200, r.text

    csrf_token = client.cookies.get("csrf_token")
    assert csrf_token, "GET /reception/login não criou o cookie CSRF"

    r = client.post(
        "/reception/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": csrf_token,
        },
        follow_redirects=follow_redirects,
    )

    return r
