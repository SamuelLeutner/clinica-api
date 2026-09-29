# Exercício 4 — Modelagem de ameaças com STRIDE

## 1. Misuse cases

| ID | Ator malicioso | Caso de uso abusado | Objetivo do atacante |
|---|---|---|---|
| MC-1 | Profissional de saúde autenticado | `GET /appointments/{id}` | Ler prontuário/consulta de paciente de outro profissional trocando o ID na URL (BOLA) |
| MC-2 | Usuário anônimo | `POST /auth/register` | Forjar um campo não previsto no payload (ex.: papel de admin) para escalar privilégio na criação da conta |
| MC-3 | Visitante do site da recepção | Campo `notes` de uma consulta | Persistir um `<script>` que executa no navegador de qualquer recepcionista que abrir a agenda do dia (XSS armazenado) |
| MC-4 | Terceiro que intercepta/vaza o token do laboratório parceiro | Qualquer rota humana da API | Usar o token M2M vazado para ler dados de paciente, não apenas disponibilidade de horário |
| MC-5 | Atacante externo sem credenciais | `POST /auth/token` | Força bruta de senha por tentativa e erro em massa |
| MC-6 | Profissional autenticado | `POST /appointments` | Criar consulta em nome de outro profissional (`professional_id` de colega) para depois poder editá-la como se fosse sua |

## 2. STRIDE aplicado a três componentes centrais

### 2.1 Camada de autenticação (`app/security/auth.py`)

| STRIDE | Ameaça | Mitigação |
|---|---|---|
| **S**poofing | Atacante se passa por outro usuário reutilizando/forjando um JWT | Assinatura HS256 com `JWT_SECRET_KEY` de 256+ bits fora do código-fonte; `exp` obrigatório |
| **T**ampering | Payload do JWT alterado em trânsito (ex.: mudar `role`) | Verificação de assinatura via `jose.jwt.decode` — qualquer alteração invalida a assinatura |
| **R**epudiation | Usuário nega ter feito uma ação | `jti` único por token (base para auditoria/blacklist futura); `created_by_user_id` em toda consulta |
| **I**nfo Disclosure | Mensagem de erro de login revela se o username existe | Mensagem genérica "Credenciais inválidas" para username inexistente OU senha errada |
| **D**oS | Força bruta esgota recursos de hashing bcrypt | Rate limiting de 5/min em `/auth/token` |
| **E**oP | Conta comum consegue emitir token com `role: admin` | `role` nunca é lido do body além do que o próprio registro define; MFA obrigatório para admin eleva a barreira mesmo se a senha vazar |

### 2.2 Recurso de consultas (`app/routes/appointments.py` + `permissions.py`)

| STRIDE | Ameaça | Mitigação |
|---|---|---|
| **S**poofing | — (coberto pela camada de autenticação) | — |
| **T**ampering | BOLA: profissional edita/lê consulta de colega (MC-1) | `verify_appointment_ownership` como dependency obrigatória em toda rota de consulta específica |
| **R**epudiation | Alteração de status sem rastro de quem fez | `updated_at` atualizado a cada PATCH; `created_by_user_id` gravado na criação |
| **I**nfo Disclosure | Resposta 403 confirmando que o ID existe, mas pertence a outro | Resposta **404** (não 403) quando ownership falha — não confirma existência |
| **D**oS | Listagem sem paginação em base grande | Fora de escopo deste Assessment — risco residual documentado no Ex.13 |
| **E**oP | Profissional cria consulta em nome de colega (MC-6) | `professional_id` do payload é ignorado e substituído pelo do token quando o papel é PROFISSIONAL |

### 2.3 Página HTML da recepção (`app/routes/reception.py` + templates)

| STRIDE | Ameaça | Mitigação |
|---|---|---|
| **S**poofing | Sessão de recepção sequestrada via cookie roubado | Cookie `httponly` + `samesite=lax`; expiração de 15 min |
| **T**ampering | — | — |
| **R**epudiation | — | — |
| **I**nfo Disclosure | Página de agenda acessível sem login | `get_current_user_from_cookie` redireciona para login se não houver cookie válido |
| **D**oS | — | — |
| **E**oP | XSS armazenado no campo `notes` rouba cookie de sessão da recepção (MC-3) | Auto-escape do Jinja2 na saída (defesa principal) + rejeição de padrões óbvios de script na entrada (defesa em profundidade) + cookie `httponly` (reduz impacto mesmo se um XSS passar) |

## 3. Threat model consolidado

### Ativos
- **A1** — Dados de paciente (CPF, contato, prontuário/notas de consulta) — dado sensível LGPD.
- **A2** — Credenciais de usuário (senha com hash, secret MFA).
- **A3** — Token JWT de sessão (humano e M2M).
- **A4** — Disponibilidade da API para a operação da clínica.

### Superfícies de ataque
- API JSON pública (`/patients`, `/appointments`, `/professionals`, `/auth/*`).
- Página HTML da recepção (`/reception/*`) — superfície de navegador, sujeita a XSS/clickjacking além dos riscos de API.
- Endpoint M2M do laboratório (`/lab/disponibilidade`, `/auth/lab-token`) — superfície exposta a uma organização externa, fora do controle direto da clínica.

### Ameaças priorizadas → mitigação → rastreabilidade

| ID | Ameaça (STRIDE) | Ativo afetado | Mitigação | Testado em |
|---|---|---|---|---|
| T-1 | EoP — escalonar privilégio via mass-assignment (MC-2) | A1, A2 | `extra='forbid'` em todos os schemas de entrada | `test_privilege_escalation_via_mass_assignment_blocked` |
| T-2 | Tampering — BOLA (MC-1) | A1 | `verify_appointment_ownership` centralizado | `test_bola_blocked_on_get/update/list` |
| T-3 | EoP — XSS stored (MC-3) | A1, sessão da recepção | Auto-escape Jinja2 + validação de entrada + cookie httponly | `test_agenda_page_escapes_html_in_notes`, `test_stored_xss_payload_rejected_at_input` |
| T-4 | Spoofing/EoP — token M2M vazado usado fora de escopo (MC-4) | A1, A3 | Claim `scope` isola token M2M das rotas humanas | `test_m2m_token_cannot_access_human_routes` |
| T-5 | DoS — força bruta de login (MC-5) | A2, A4 | Rate limiting 5/min em `/auth/token` | Verificado manualmente (ver Ex.10); automatizável com `freezegun` se o escopo crescer |
| T-6 | Tampering — criar consulta em nome de colega (MC-6) | A1 | `professional_id` do token sobrepõe o do payload | `test_professional_cannot_create_appointment_for_colleague` |

Este documento é a referência oficial consultada pelos Exercícios 8, 9, 12
e 13 — cada correção de vulnerabilidade e cada teste de segurança
adicionado nos exercícios seguintes aponta de volta para um ID desta
tabela (rastreabilidade completa, exigida no relatório final).
