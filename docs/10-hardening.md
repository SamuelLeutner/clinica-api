# Exercício 10 — Hardening de rede e proteção contra abuso

## Contexto de auditoria
Um auditor externo já reprovou outro serviço de saúde por CORS com
wildcard e ausência de headers básicos. Os três controles abaixo evitam
exatamente essa reprovação.

## 1. CORS com allowlist explícita
`app/main.py` configura `CORSMiddleware` com `allow_origins=settings.cors_origins_list`,
lido de `CORS_ALLOWED_ORIGINS` no `.env` — nunca `["*"]`. Evidência real
(`docs/evidence/ex10-hardening.txt`): uma origem não listada
(`https://site-malicioso.com`) não recebe o header
`Access-Control-Allow-Origin` na resposta; a origem autorizada
(`http://localhost:5173`) recebe.

## 2. Headers de segurança (`app/security/headers.py`)
Aplicados via middleware a toda resposta:
- `Strict-Transport-Security` (HSTS) — força HTTPS em requisições futuras do navegador.
- `X-Frame-Options: DENY` — impede embutir a página da recepção em `<iframe>` de outro site (clickjacking).
- `X-Content-Type-Options: nosniff` — impede MIME sniffing.
- `Content-Security-Policy: default-src 'self'` — reforço extra, mesmo com XSS já mitigado na origem (Jinja2).

Evidência real confirmando os quatro headers presentes na resposta de
`/health`: `docs/evidence/ex10-hardening.txt`.

## 3. Rate limiting diferenciado no login
`/auth/token` tem limite de `5/minute` por IP (via slowapi), configurável
por `LOGIN_RATE_LIMIT` — mais restritivo que o limite global da API
(`100/minute`), porque é o endpoint que já sofreu tentativas de força
bruta. Evidência real: 6 tentativas de login em sequência rápida — as
5 primeiras retornam 401 (credencial errada), a 6ª já retorna
**HTTP 429** (`docs/evidence/ex10-hardening.txt`).

Por que o limite é por IP e não por conta: limitar por `username` sujeitaria
uma conta legítima a ficar bloqueada por um atacante que erra a senha
dela de propósito (ataque de negação de serviço direcionado a uma vítima
específica) — ver STRIDE T-1/T-8 em `docs/04-stride-threat-model.md`.
