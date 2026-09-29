# Exercício 9 — Correção de vulnerabilidades de entrada e saída

Correção centralizada — cada fix vive em UM lugar, aplicado via
dependency/schema/config, não repetido endpoint a endpoint (para não
repetir o erro do Exercício 8 em endpoints futuros).

## Correção 1 — BOLA → ownership check centralizado

**Depois:**
```python
# app/security/permissions.py
def verify_appointment_ownership(
    appointment_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> Appointment:
    appointment = session.get(Appointment, appointment_id)
    if appointment is None:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")
    if current_user.role == UserRole.PROFISSIONAL and appointment.professional_id != current_user.professional_id:
        raise HTTPException(status_code=404, detail="Consulta não encontrada")  # 404, não 403
    return appointment
```
Aplicado como dependency em `GET/PATCH/DELETE /appointments/{id}` e
`PATCH /appointments/{id}/status` — impossível esquecer em um desses
quatro sem que a assinatura da função mude visivelmente. A listagem
(`GET /appointments`) usa a mesma regra dentro do próprio handler,
filtrando a query por `professional_id` antes de tocar o banco.

**Evidência do mesmo ataque, agora bloqueado
(`docs/evidence/ex9-bola-depois.txt`):** `test_bola_blocked_on_get`
passa — `GET /appointments/{id}` de Bruno sobre a consulta de Ana agora
retorna **HTTP 404**, não 200. `test_bola_blocked_on_update` e
`test_bola_blocked_on_list` cobrem os outros dois pontos de entrada da
mesma classe de falha.

## Correção 2 — XSS armazenado → output encoding via auto-escape do Jinja2

**Depois:** `Jinja2Templates(directory="app/templates")` do FastAPI
mantém `autoescape=True` por padrão para arquivos `.html` — e nenhum
template deste projeto usa o filtro `|safe`. O comentário em
`agenda.html` documenta explicitamente essa decisão para quem for mexer
no template no futuro.

**Evidência do mesmo payload, agora inofensivo:**
`test_agenda_page_escapes_html_in_notes` grava uma nota com
`<b>muito forte</b>` (marcação que passa pela validação de entrada, para
provar que a defesa real é a saída) e confirma que o HTML final contém
`&lt;b&gt;muito forte&lt;/b&gt;` — texto literal, não uma tag
renderizada. `test_stored_xss_payload_rejected_at_input` cobre a camada
adicional: um payload óbvio de `<script>` nem chega a ser salvo, rejeitado
já na validação Pydantic (defesa em profundidade, não a defesa
principal).

## Correção 3 — Validação whitelist/regex + `extra='forbid'`

**Depois (`app/models/schemas.py`):** todo schema de entrada tem
`model_config = ConfigDict(extra="forbid")`; campos como `cpf`,
`phone`, `license_number` e `notes` têm `field_validator` com regex de
whitelist (formato fechado) em vez de blacklist (tentar prever todo
formato inválido).

**Evidência:** `test_privilege_escalation_via_mass_assignment_blocked`
— tentativa de registrar usuário com campo extra (`is_active_override`)
recebe **HTTP 422**, a requisição inteira é rejeitada, não apenas o
campo extra ignorado.

## Correção 4 — Middleware JWT centralizado

Não há decodificação de JWT espalhada pelos routers: `get_current_user`
(API JSON) e `get_current_user_from_cookie` (HTML) são os dois únicos
pontos de decodificação em todo o projeto, e ambos reutilizam
`decode_access_token`. Isso significa que uma correção futura (ex.: nova
regra de expiração, blacklist de `jti`) precisa mudar código em um único
lugar, não em N routers.

## Endpoint adicional corrigido (mesmo padrão do Exercício 8)

Como identificado no Exercício 8, `PATCH /appointments/{id}` e
`GET /appointments` tinham o mesmo padrão de BOLA do `GET` por ID. A
mesma dependency (`verify_appointment_ownership`) foi aplicada ao PATCH,
e o filtro de `professional_id` foi aplicado à query da listagem — ambos
cobertos por teste dedicado (`test_bola_blocked_on_update`,
`test_bola_blocked_on_list`), não apenas "corrigidos de olho".
