# Exercício 13 — Capstone: auditoria final e relatório de rastreabilidade

## Matriz de rastreabilidade

| Finding / ameaça       | OWASP                                             | Exercício | Mitigação              | Evidência      |
| ---------------------- | ------------------------------------------------- | --------- | ---------------------- | -------------- |
| BOLA                   | API1 - Broken Object Level Authorization          | 8/9       | Ownership centralizado | pytest         |
| XSS Stored             | A03 - Injection                                   | 8/9       | Jinja2 autoescape      | pytest + ZAP   |
| Mass Assignment        | API3 - Broken Object Property Level Authorization | 8/9       | Pydantic extra=forbid  | pytest         |
| SQL Injection          | A03 - Injection                                   | 8/9/11    | SQLModel parametrizado | pytest         |
| Brute Force            | A07 - Authentication Failures                     | 10        | Rate limiting          | pytest         |
| CORS excessivo         | A05 - Security Misconfiguration                   | 10        | Allowlist              | pytest         |
| Headers ausentes       | A05 - Security Misconfiguration                   | 10        | Security middleware    | pytest         |
| Dependência vulnerável | A06 - Vulnerable Components                       | 12        | pip-audit              | GitHub Actions |

## 1. Escopo da auditoria final

Aplicação FastAPI integrando autenticação (JWT + bcrypt + MFA), validação
whitelist, headers de segurança, RBAC + ownership, e persistência via
SQLModel. Auditoria composta por:
- SAST real (Bandit) — `docs/12-pipeline-devsecops.md`
- SCA real (pip-audit) — `docs/12-pipeline-devsecops.md`
- **DAST real (OWASP ZAP 2.17.0, scan passivo)** — executado duas vezes
  nesta sessão: uma varredura inicial e uma segunda após corrigir os
  achados da primeira. Nenhum resultado abaixo é hipotético.
- Suíte pytest (16 testes, `tests/`) — autorização, XSS, SQLi, CSRF
- Auditoria manual da especificação OpenAPI (`/openapi.json`)

## 2. Execução do OWASP ZAP

Metodologia: ZAP em modo daemon, especificação OpenAPI da aplicação
importada via `/JSON/openapi/action/importUrl/` (gera requisição real
para cada endpoint declarado) + spider tradicional para a página HTML da
recepção. 78 mensagens HTTP analisadas pelo motor de scan passivo em
ambos os runs.

### Varredura 1 (antes das correções deste exercício)
`docs/evidence/zap/zap-report-antes.html` / `zap-alerts-antes.json`

| Severidade | Achado | Ocorrências |
|---|---|---|
| Medium | CSP: Failure to Define Directive with No Fallback | 2 |
| Medium | Absence of Anti-CSRF Tokens | 2 |
| Informational | Authentication Request Identified | 2 |

### Varredura 2 (depois das correções deste exercício)
`docs/evidence/zap/zap-report-depois.html` / `zap-alerts-depois.json`

| Severidade | Achado | Ocorrências |
|---|---|---|
| Informational | Authentication Request Identified | 2 |
| Informational | Session Management Response Identified | 1 |

**Resultado: 4 achados Medium → 0. Nenhum achado High em nenhuma das
duas varreduras.**

## 3. Rastreabilidade: finding → categoria OWASP → correção → evidência

| # | Finding do ZAP | Categoria OWASP | Correção aplicada | Evidência da correção |
|---|---|---|---|---|
| 1 | CSP: Failure to Define Directive with No Fallback | A05:2021 Security Misconfiguration | Adicionadas as diretivas `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'` ao header CSP (`app/security/headers.py`) — `frame-ancestors` não herda de `default-src`, precisava ser explícita | Varredura 2 (0 ocorrências) |
| 2 | Absence of Anti-CSRF Tokens (`POST /reception/login`) | A01:2021 Broken Access Control (CSRF é um caso de controle de acesso quebrado por falsificação de solicitação) | Implementado double-submit cookie (`app/security/csrf.py`) — token gerado no GET, exigido como campo oculto no POST, comparado com `hmac.compare_digest` contra o cookie | Varredura 2 (0 ocorrências) + `test_reception_login_without_csrf_token_rejected` (HTTP 403 com token forjado) |

Além dos achados do ZAP, esta tabela estende a rastreabilidade aos
achados do Exercício 8/threat model, já corrigidos e testados antes desta
varredura (por isso o ZAP não os re-detecta — o motor de scan passivo
não teria como enxergar BOLA ou lógica de autorização, que são falhas de
regra de negócio, não de padrão de tráfego HTTP):

| # | Finding (identificado manualmente, Ex.8) | Categoria OWASP | Correção | Evidência |
|---|---|---|---|---|
| 3 | BOLA em `/appointments/{id}` | A01:2021 Broken Access Control (API1:2023) | `verify_appointment_ownership` centralizada | `docs/evidence/ex9-bola-depois.txt` + `test_bola_blocked_on_get/_update/_list` |
| 4 | XSS armazenado em `notes` | A03:2021 Injection | Validação de entrada + auto-escape Jinja2 (nunca `\|safe`) | `test_agenda_page_escapes_html_in_notes` |
| 5 | Mass assignment / forja de campo | API3:2023 Broken Object Property Level Authorization | Pydantic `extra="forbid"` em todo schema de entrada | `test_privilege_escalation_via_mass_assignment_blocked` |

## 4. Testes automatizados de segurança (mocking + entrada + autorização)

`tests/` — 16 testes, 0 falhas na execução mais recente:
- `test_appointments.py` — caminho de sucesso (Ex.1)
- `test_authorization.py` — 9 testes: RBAC básico (Ex.6) + BOLA, mass
  assignment, isolamento M2M, XSS na entrada (Ex.12, rastreável ao
  threat model do Ex.4)
- `test_security_fixes.py` — 6 testes: XSS na saída (auto-escape), SQLi
  sem efeito, autenticação obrigatória na agenda, CSRF bloqueado/aceito

O "mocking" exigido pelo enunciado deste exercício está no MFA: os testes
não integram com um autenticador real — geram o código TOTP diretamente
a partir do `mfa_secret` do banco de teste via `pyotp.TOTP(...).now()`,
simulando o que um app autenticador faria sem depender de infraestrutura
externa.

## 5. Auditoria da especificação OpenAPI

`GET /openapi.json` foi inspecionada manualmente. Achados:
- Todo endpoint de escrita declara corretamente os status codes de erro
  (401/403/404/422) nos schemas de resposta gerados automaticamente pelo
  FastAPI a partir das `HTTPException` levantadas — não há endpoint
  "otimista" que só documenta o caminho de sucesso.
- `AppointmentRead`, `PatientRead`, `UserRead` — os únicos schemas de
  resposta usados nas rotas — nunca incluem `hashed_password`,
  `mfa_secret`, `created_by_user_id` ou `updated_at`, confirmando de
  fora para dentro (pela spec, não só lendo o código) que o Exercício 2
  está de fato refletido no contrato público da API.
- Nenhum endpoint expõe parâmetro de paginação ou filtro que aceite SQL
  bruto ou nome de coluna livre — toda ordenação/filtro é fixa no código
  (`ORDER BY Appointment.scheduled_at`), eliminando uma classe inteira de
  injeção via nome de campo dinâmico antes mesmo de precisar de correção.

## 6. Risco residual

| Risco | Por que não foi (e não precisa ser) eliminado | Aceitável para deploy? |
|---|---|---|
| `ecdsa` 0.19.2 (CVE-2024-23342, CVSS 7.4) sem fix planejado pelo mantenedor | Dependência transitiva de `python-jose`; a aplicação assina JWT apenas com HS256 (HMAC simétrico) — o caminho de código vulnerável (operações ECDSA/ES256) nunca é exercido. Documentado como exceção explícita no security gate (`docs/12-pipeline-devsecops.md`) | **Sim** — risco teórico sem caminho de exploração alcançável neste sistema. Recomendação: revisitar se a aplicação algum dia passar a suportar ES256 ou qualquer operação ECDSA |
| Rate limiting em memória (slowapi, não Redis) | Em múltiplas réplicas do processo (scale-out horizontal), cada réplica tem seu próprio contador — um atacante distribuindo requisições entre réplicas poderia, na prática, exceder o limite nominal de 5/min | **Aceitável para o estágio atual** (deploy de instância única/MVP) — **bloqueante antes de qualquer scale-out horizontal em produção**, quando um backend compartilhado (Redis) passa a ser obrigatório |
| MFA simulado via TOTP sem app autenticador real distribuído às contas admin no momento do cadastro | O fluxo técnico (TOTP real, `pyotp`) é idêntico ao de produção; falta apenas a etapa de UX de mostrar o QR code/secret uma única vez no cadastro, que é responsabilidade de produto/frontend, não da API | **Sim** — a API já força e valida MFA corretamente; a distribuição do secret é responsabilidade da camada de UI, fora do escopo desta API |
| Token JWT sem blacklist ativa de `jti` (campo já presente, mecanismo de revogação não implementado) | Expiração curta (15 min) limita a janela de exposição de um token roubado mesmo sem revogação ativa | **Aceitável para o volume atual** — recomendação de melhoria futura antes de a clínica escalar para múltiplas unidades com maior superfície de dispositivos |

**Recomendação final: autorizar o deploy.** Nenhum risco residual listado
envolve exposição direta e imediata de dado de paciente sem uma
mitigação compensatória já ativa (expiração curta de token, ausência de
caminho de código alcançável, ou responsabilidade correta atribuída a
outra camada do sistema). Os dois únicos achados de severidade real
encontrados por ferramenta automatizada nesta sessão (CSP incompleto e
CSRF ausente) foram corrigidos e reconfirmados por uma segunda varredura
do mesmo scanner, não apenas por leitura de código.
