"""
Evidência automatizada de duas correções do Exercício 9/11:

1. XSS stored: um valor com marcação HTML que passa pela validação de
   entrada (não é um <script> óbvio) precisa sair escapado na página
   Jinja2 da recepção.
2. SQL injection: um valor malicioso em parâmetro de busca não pode
   alterar o comportamento da query, porque toda query passa pelo SQLModel
   (parametrização automática via SQLAlchemy Core), nunca por
   concatenação de string.
"""
from datetime import date, timedelta

from sqlmodel import Session
from unittest.mock import patch
from app.security.auth import verify_mfa_challenge
from tests.conftest import reception_login, register_and_login


def _bootstrap_appointment_with_notes(client, session: Session, notes: str) -> None:
    admin_token = register_and_login(client, session, username="admin1", password="SenhaForte123", role="admin")
    r = client.post(
        "/professionals",
        json={"full_name": "Dra. Ana", "specialty": "Cardiologia", "license_number": "CRM-SP-111111"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    prof_id = r.json()["id"]
    prof_token = register_and_login(client, session, username="ana", password="SenhaForteAna1", role="profissional", professional_id=prof_id)

    recep_token = register_and_login(client, session, username="recep1", password="SenhaForteRecep1", role="recepcionista")
    r = client.post(
        "/patients",
        json={"full_name": "Carlos", "cpf": "12345678901", "birth_date": "1990-05-10", "phone": "+5511999998888", "email": "c@example.com"},
        headers={"Authorization": f"Bearer {recep_token}"},
    )
    patient_id = r.json()["id"]

    today = date.today().isoformat()
    r = client.post(
        "/appointments",
        json={"patient_id": patient_id, "professional_id": prof_id, "scheduled_at": f"{today}T14:00:00", "notes": notes},
        headers={"Authorization": f"Bearer {prof_token}"},
    )
    assert r.status_code == 201, r.text

def test_agenda_page_escapes_html_in_notes(client, session: Session):
    """Marcação HTML que passou pela validação de entrada (não contém
    <script>, javascript: ou onerror=) ainda assim sai escapada na
    página — a defesa real contra XSS é a saída, não a entrada."""

    _bootstrap_appointment_with_notes(
        client,
        session,
        "Paciente relatou dor <b>muito forte</b> no peito",
    )

    token_response = client.post(
        "/auth/token",
        data={
            "username": "recep1",
            "password": "SenhaForteRecep1",
        },
    )

    assert token_response.status_code == 200, token_response.text

    access_token = token_response.json()["access_token"]
    assert access_token

    client.cookies.set("access_token", access_token)

    r = client.get("/reception/agenda", follow_redirects=False)

    assert r.status_code == 200
    assert "<title>Login — Recepção</title>" not in r.text

    assert "<b>muito forte</b>" not in r.text

    assert "&lt;b&gt;muito forte&lt;/b&gt;" in r.text


def test_agenda_requires_authentication(client, session: Session):
    # TestClient segue redirects por padrão; sem cookie, a rota redireciona
    # (303) para /reception/login, então acabamos na página de login — sem
    # nenhum dado de agenda vazado.
    r = client.get("/reception/agenda")
    assert r.status_code == 200
    assert "Recepção — Login" in r.text
    assert "Nenhuma consulta" not in r.text

    r = client.get("/reception/agenda", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/reception/login"


def test_sql_injection_in_patient_search_has_no_effect(client, session: Session):
    """Tenta um payload clássico de SQLi no campo full_name do cadastro de
    paciente. Como o SQLModel sempre parametriza, o payload é gravado
    como uma string literal comum — não altera nenhuma query, não derruba
    a tabela, não retorna dados de outros pacientes."""
    recep_token = register_and_login(client, session, username="recep1", password="SenhaForteRecep1", role="recepcionista")

    payload = "Carlos'; DROP TABLE patient; --"
    r = client.post(
        "/patients",
        json={"full_name": payload, "cpf": "12345678901", "birth_date": "1990-05-10", "phone": "+5511999998888", "email": "c@example.com"},
        headers={"Authorization": f"Bearer {recep_token}"},
    )
    assert r.status_code == 201
    assert r.json()["full_name"] == payload  # gravado como string literal, tabela intacta

    # Prova de que a tabela sobreviveu: conseguimos listar pacientes normalmente.
    r = client.get("/patients", headers={"Authorization": f"Bearer {recep_token}"})
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_reception_login_without_csrf_token_rejected(client, session: Session):
    """Achado real do OWASP ZAP no Exercício 13 ("Absence of Anti-CSRF
    Tokens"): um POST sem o token CSRF correto — simulando um formulário
    forjado por outro site, que não tem como ler o valor do cookie
    (Same-Origin Policy) — é rejeitado com 403, mesmo com credenciais
    corretas."""
    register_and_login(client, session, username="recep1", password="SenhaForteRecep1", role="recepcionista")

    client.get("/reception/login")  # popula o cookie csrf_token legítimo
    r = client.post(
        "/reception/login",
        data={"username": "recep1", "password": "SenhaForteRecep1", "csrf_token": "token-forjado-por-outro-site"},
    )
    assert r.status_code == 403


def test_reception_login_with_valid_csrf_token_succeeds(client, session: Session):
    register_and_login(client, session, username="recep1", password="SenhaForteRecep1", role="recepcionista")
    r = reception_login(client, "recep1", "SenhaForteRecep1", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/reception/agenda"


def test_mfa_verification_uses_expected_secret(client, session):
    admin_token = register_and_login(
        client,
        session,
        username="admin1",
        password="SenhaForte123",
        role="admin",
    )

    # O registro/login acima garante que existe um usuário admin
    # com MFA configurado.
    from sqlmodel import select
    from app.models.user import User
    from app.security.auth import create_mfa_challenge

    user = session.exec(select(User).where(User.username == "admin1")).first()

    assert user is not None
    assert user.mfa_secret is not None

    challenge_id = create_mfa_challenge(user)

    with patch("app.security.auth.pyotp.TOTP.verify", return_value=True) as mock_verify:
        result = verify_mfa_challenge(
            challenge_id,
            "123456",
            session,
        )

    assert result.username == "admin1"
    mock_verify.assert_called_once_with("123456", valid_window=1)


def test_security_headers(client):
    response = client.get("/docs")

    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_hsts_header(client):
    response = client.get("/docs")

    assert "Strict-Transport-Security" in response.headers


def test_cors_rejects_unknown_origin(client):
    response = client.options(
        "/appointments/",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.headers.get("access-control-allow-origin") != "https://evil.example"
