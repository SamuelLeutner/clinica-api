# Exercício 5 — Arquitetura de segurança e vetores de ataque

## 1. Partições do sistema

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENTES (3 tipos)                        │
│  Frontend JSON  │  Navegador da recepção  │  Laboratório (M2M)   │
└─────────┬───────────────────┬──────────────────────┬────────────┘
          │ Bearer JWT        │ Cookie httponly       │ Bearer JWT
          │ (OAuth2PasswordBearer)  (sessão HTML)      (scope M2M)
          ▼                   ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     PARTIÇÃO: Edge / Middleware                  │
│   CORS allowlist → Security Headers → Rate Limiting              │
└─────────────────────────────┬──────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                  PARTIÇÃO: Camada de Aplicação                   │
│  ┌───────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ Autenticação   │→ │ Autorização        │→ │ Routers          │ │
│  │ (JWT/bcrypt/   │  │ (RBAC + ownership) │  │ (appointments,   │ │
│  │  MFA/OAuth2 M2M)│  │                    │  │  patients, ...)  │ │
│  └───────────────┘  └──────────────────┘  └────────┬─────────┘  │
│                                                       │            │
│                                            ┌──────────▼────────┐  │
│                                            │ Jinja2 Templates   │  │
│                                            │ (auto-escape)      │  │
│                                            └────────────────────┘ │
└──────────────────────────────┬──────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                  PARTIÇÃO: Persistência (SQLModel)                │
│         Engine + Session por request, queries parametrizadas      │
└─────────────────────────────┬──────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│           PARTIÇÃO: Infraestrutura (fora do código da app)        │
│    Banco relacional · Variáveis de ambiente (.env) · TLS/HTTPS    │
│    CI/CD (GitHub Actions) · Scanner OWASP ZAP                     │
└─────────────────────────────────────────────────────────────────┘
```

A fronteira mais importante para o negócio é entre **Camada de
Aplicação** e **Persistência**: é onde uma falha de autorização (partição
de cima) se torna um vazamento real de dado de paciente (partição de
baixo) se não houver dupla checagem. Por isso `verify_appointment_ownership`
roda *antes* de qualquer query ao banco, nunca depois.

## 2. Fluxo de dados entre componentes

1. Cliente autentica (`/auth/token`, `/auth/mfa/verify` ou `/auth/lab-token`) → recebe JWT.
2. Cliente chama um endpoint de recurso com o JWT no header `Authorization` (API JSON) ou cookie (HTML).
3. `get_current_user` / `get_current_user_from_cookie` decodifica o token e carrega o usuário do banco.
4. `require_roles` / `verify_appointment_ownership` decide se o usuário pode prosseguir.
5. O router acessa o SQLModel, que gera SQL parametrizado.
6. A resposta passa por um `response_model` (JSON) ou por um template Jinja2 com auto-escape (HTML) antes de sair.

## 3. Vetores de ataque nos três eixos de segurança de APIs

### 3.1 Design
- **Vetor:** desenhar um único fluxo OAuth2 "genérico" para humano e M2M teria misturado claims de usuário com claims de cliente de sistema, abrindo brecha para um token M2M ser aceito onde não devia.
  **Decisão de design que mitiga:** dois fluxos completamente separados (`OAuth2PasswordBearer` para humano, Client Credentials para M2M), com claim `scope` como discriminador explícito verificado nos dois sentidos (`get_current_user` rejeita token com `scope`; `require_lab_scope` exige `scope` correto).
- **Vetor:** expor `PatientRead` com CPF completo em toda listagem facilitaria enumeração/correlação de pacientes por terceiros com acesso de leitura básico.
  **Mitigação de design:** CPF só aparece em `PatientReadDetailed`, usado apenas no endpoint de detalhe, não na listagem.

### 3.2 Implementação
- **Vetor:** BOLA por esquecimento de checagem em um endpoint novo (Exercício 8).
  **Mitigação:** ownership check como *dependency* reutilizável, não como `if` copiado em cada handler — reduz a chance de um desenvolvedor futuro esquecer a checagem.
- **Vetor:** XSS armazenado por template que usa `|safe` "só dessa vez".
  **Mitigação:** nenhum template deste projeto usa o filtro `|safe`; auto-escape do Jinja2Templates é o padrão do FastAPI e não foi desligado em lugar nenhum.
- **Vetor:** SQL injection por query montada com f-string em vez de SQLModel.
  **Mitigação:** todo acesso a dado passa pelo SQLModel/SQLAlchemy Core; nenhuma string SQL é montada manualmente no projeto (verificável por grep — ver Exercício 8).

### 3.3 Infraestrutura
- **Vetor:** CORS com wildcard permitindo qualquer origem ler resposta autenticada via browser.
  **Mitigação:** allowlist explícita via `CORS_ALLOWED_ORIGINS` (Exercício 10).
- **Vetor:** credencial de banco/JWT hardcoded no repositório, vazada em um `git log`.
  **Mitigação:** `Settings` via `BaseSettings` lendo de `.env` (nunca commitado — está no `.gitignore`); apenas `.env.example` sem segredos reais é versionado.
- **Vetor:** tráfego em texto plano (HTTP) expondo JWT em trânsito.
  **Mitigação:** header HSTS instruindo o browser a sempre usar HTTPS a partir da primeira visita segura.

Esta visão de partições orienta diretamente a decisão de exposição de
autenticação do Exercício 6: como o laboratório parceiro já está numa
partição de confiança mais baixa (fora da organização), seu fluxo de
autenticação precisa ser tecnicamente incapaz de alcançar as partições
de cima reservadas a usuários humanos — não bastaria documentar isso em
contrato.
