from sqlmodel import Session

from tests.conftest import register_and_login


def test_create_appointment_success_path(client, session: Session, tomorrow_iso: str):
    """Caminho de sucesso: profissional autenticado cria uma consulta para
    um paciente existente e recebe 201 com os campos esperados."""
    admin_token = register_and_login(client, session, username="admin1", password="SenhaForte123", role="admin")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    r = client.post(
        "/professionals",
        json={"full_name": "Dra. Ana Souza", "specialty": "Cardiologia", "license_number": "CRM-SP-123456"},
        headers=admin_headers,
    )
    assert r.status_code == 201
    professional_id = r.json()["id"]

    prof_token = register_and_login(
        client, session, username="ana", password="SenhaForteAna1", role="profissional", professional_id=professional_id
    )
    prof_headers = {"Authorization": f"Bearer {prof_token}"}

    recep_token = register_and_login(client, session, username="recep1", password="SenhaForteRecep1", role="recepcionista")
    r = client.post(
        "/patients",
        json={
            "full_name": "Carlos Pereira",
            "cpf": "12345678901",
            "birth_date": "1990-05-10",
            "phone": "+5511999998888",
            "email": "carlos@example.com",
        },
        headers={"Authorization": f"Bearer {recep_token}"},
    )
    assert r.status_code == 201
    patient_id = r.json()["id"]

    r = client.post(
        "/appointments",
        json={
            "patient_id": patient_id,
            "professional_id": professional_id,
            "scheduled_at": f"{tomorrow_iso}T10:00:00",
            "notes": "Retorno de rotina",
        },
        headers=prof_headers,
    )

    assert r.status_code == 201
    body = r.json()
    assert body["patient_id"] == patient_id
    assert body["professional_id"] == professional_id
    assert body["status"] == "agendada"
    # Campos de auditoria interna nunca aparecem no response_model.
    assert "created_by_user_id" not in body
    assert "updated_at" not in body
