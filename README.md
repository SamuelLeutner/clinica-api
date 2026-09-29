# Clínica — API de Agendamento de Consultas

API REST em FastAPI para agendamento de consultas médicas, construída com
segurança desde a primeira linha de código (dado de saúde, LGPD). Este
README é o relatório técnico consolidado exigido na entrega — explica as
decisões de segurança de cada exercício e onde encontrar o código e a
evidência de cada uma.

## Como rodar

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   
uvicorn app.main:app --reload
```

Docs interativas: `http://127.0.0.1:8000/docs`
Painel HTML da recepção: `http://127.0.0.1:8000/reception/login`

## Como rodar os testes

```bash
pytest -v
```
20 testes, cobrindo caminho de sucesso, autorização (RBAC + BOLA), XSS
(entrada e saída), SQL injection, mass assignment, isolamento M2M e CSRF.

## Estrutura do projeto

```
app/
  config.py          # Settings via BaseSettings + .env (Ex.11)
  database.py        # SQLModel engine + injeção de sessão (Ex.11)
  main.py            # monta routers, CORS, headers, rate limit
  models/            # SQLModel (tabelas) + Pydantic (schemas de entrada/saída)
  routes/            # appointments, patients, professionals, auth, reception (HTML), lab (M2M)
  security/          # auth (JWT/bcrypt/MFA), permissions (RBAC/ownership), m2m, csrf, headers, rate_limit
  templates/          # Jinja2 com herança e auto-escape (Ex.2)
tests/                # pytest — ver seção acima
docs/                 # um arquivo por exercício (03 a 13) + evidências reais em docs/evidence/
.github/workflows/    # pipeline DevSecOps (Ex.12)
```

## Decisões de segurança por exercício

**Ex.1 — Fundação.** FastAPI modularizado em `routes/models/database`,
recurso `appointments` completo via `APIRouter`, primeiro teste pytest
(`tests/test_appointments.py`).

**Ex.2 — Exposição de dados e templates seguros.** `response_model`
explícito em toda rota de leitura (allowlist de campos — nunca o modelo
de tabela bruto); Jinja2 com herança (`base.html`) e auto-escape nunca
desligado. Ver `app/models/schemas.py` e `app/templates/`.

**Ex.3 — CIA + frameworks + DFD.** `docs/03-cia-triad-dfd.md`.

**Ex.4 — STRIDE + threat model.** `docs/04-stride-threat-model.md` — é a
referência oficial reusada nos Exercícios 9, 12 e 13.

**Ex.5 — Arquitetura e vetores de ataque.** `docs/05-arquitetura-seguranca.md`.

**Ex.6/7 — Autenticação, autorização e M2M.** JWT + bcrypt + MFA real via
TOTP (`app/security/auth.py`); RBAC + ownership centralizada
(`app/security/permissions.py`); OAuth2 Client Credentials isolado por
`scope` para o laboratório parceiro (`app/security/m2m.py`).

**Ex.8 — Vulnerabilidades identificadas.** `docs/08-vulnerabilidades-owasp.md`
— BOLA, XSS armazenado e mass assignment, com evidência de exploração
real em `docs/evidence/`.

**Ex.9 — Correções.** `docs/09-correcoes-aplicadas.md` — evidência do
mesmo ataque, agora bloqueado, para cada vulnerabilidade do Ex.8.

**Ex.10 — Hardening.** CORS allowlist, headers (HSTS/X-Frame-Options/
X-Content-Type-Options), rate limit diferenciado no login — evidência
real de execução em `docs/evidence/ex10-hardening.txt`, doc em
`docs/10-hardening.md`.

**Ex.11 — Persistência.** SQLModel com queries sempre parametrizadas,
`BaseSettings` + `.env` (nunca credencial hardcoded) — `docs/11-persistencia.md`.

**Ex.12 — Pipeline DevSecOps.** Fases do SDLC justificadas, CVSS
calculado manualmente para cada achado, security gate real em
`.github/workflows/security.yml` (testado localmente com dados reais do
Bandit e do pip-audit) — `docs/12-pipeline-devsecops.md`.

**Ex.13 — Capstone.** OWASP ZAP 2.17.0 rodado de verdade (não simulado)
duas vezes — antes e depois de corrigir os 2 achados Medium reais que
apareceram (CSP incompleto, CSRF ausente). Rastreabilidade completa
finding → OWASP → correção → evidência, e avaliação de risco residual
em `docs/13-capstone-report.md`.