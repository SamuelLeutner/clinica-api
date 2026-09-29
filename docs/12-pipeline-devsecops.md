# Exercício 12 — Pipeline DevSecOps e auditoria automatizada

## Security Gate

O pipeline utiliza quatro categorias de análise:

| Ferramenta | Tipo                        | Fase do SDLC                |
| ---------- | --------------------------- | --------------------------- |
| Bandit     | SAST                        | CI / Pull Request           |
| pip-audit  | SCA                         | CI / Pull Request           |
| pytest     | Security Functional Testing | CI / Pull Request           |
| OWASP ZAP  | DAST                        | CI / ambiente de integração |

### Critério de bloqueio

O pipeline bloqueia alterações quando forem identificadas vulnerabilidades classificadas como HIGH ou CRITICAL.

Para vulnerabilidades classificadas por CVSS, o critério adotado é:

- CVSS >= 9.0: CRITICAL → bloqueia
- CVSS >= 7.0: HIGH → bloqueia
- CVSS >= 4.0: MEDIUM → registra e acompanha
- CVSS < 4.0: LOW → registra

Além do CVSS, o impacto de negócio é considerado.

Como a aplicação processa dados relacionados à saúde, vulnerabilidades que possam permitir acesso não autorizado, alteração ou exposição de dados de pacientes são consideradas de alto impacto de negócio mesmo quando a classificação técnica isolada não representar corretamente o impacto operacional.

### IAST

IAST foi analisado, mas não foi adotado neste projeto devido ao escopo e à complexidade operacional da ferramenta.

Os testes pytest não são classificados como IAST. Eles representam testes funcionais automatizados de segurança derivados do threat model.

## 1. Em que fase do SDLC cada tipo de ferramenta atua, e por quê

| Ferramenta | Tipo | Fase do SDLC | Justificativa |
|---|---|---|---|
| **Bandit** | SAST | **Code / Commit** — roda em todo push e PR, antes de qualquer merge | Falha de segurança em código (ex.: uso de `eval`, hash fraco) é mais barata de corrigir quanto mais cedo é detectada. Bandit não precisa de app rodando, então roda em segundos a cada commit — não há motivo para adiar. |
| **pip-audit** | SCA (dependency scanning) | **Build / Commit**, roda no mesmo job do Bandit + agendado diariamente (`schedule: cron`) | Diferente do SAST, uma dependência pode ficar vulnerável **sem nenhuma mudança no nosso código** — uma CVE nova é publicada num pacote já em produção. Por isso o job precisa rodar não só em PR, mas periodicamente, independente de haver commit novo. |
| **pytest (autorização/segurança)** | Teste funcional de segurança (equivalente a IAST leve) | **Test** — roda em todo PR, depois do SAST | Testa comportamento real da aplicação (BOLA bloqueado, XSS rejeitado, M2M isolado) — precisa da aplicação de fato instanciada (via `TestClient`), diferente do SAST que só lê texto do código. Colocamos depois do SAST no pipeline porque é mais lento; falhar rápido primeiro (SAST) economiza CI. |
| **OWASP ZAP (baseline/passivo)** | DAST | **Staging / pré-deploy**, nunca em produção | DAST precisa de uma instância HTTP real respondendo — só faz sentido depois do build, contra um ambiente efêmero (não produção, para não gerar tráfego de teste em dado real). É a última barreira antes do deploy, porque pega classes de falha que só aparecem no tráfego HTTP real (headers ausentes, cookies sem flag, etc.), não visíveis lendo código-fonte. |

**IAST** (instrumentação em runtime, ex.: agentes tipo Contrast/Checkmarx
IAST) foi avaliado e **descartado para este projeto**: exige um agente de
instrumentação específico da linguagem rodando dentro do processo da
aplicação durante os testes, o que adiciona complexidade de
infraestrutura desproporcional ao tamanho do time e da aplicação neste
estágio. A combinação SAST (código) + testes funcionais de autorização
(comportamento) + DAST (runtime) já cobre as três perspectivas que o IAST
tentaria unificar, com uma fração do custo de operação.

## 2. Priorização de vulnerabilidades — CVSS + impacto de negócio

Vetores CVSS v3.1 calculados manualmente pela fórmula oficial (não
estimados "no olho"), documentados abaixo para auditoria.

| ID (threat model) | Vulnerabilidade | Vetor CVSS v3.1 | Score | Severidade | Impacto de negócio |
|---|---|---|---|---|---|
| T-2 | BOLA em `/appointments/{id}` (Ex.8) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **8.1** | High | **Crítico para o negócio** — exposição direta de prontuário de saúde de terceiros, violação de LGPD com risco de multa e obrigação de notificação à ANPD |
| T-4 | Mass assignment / forja de campo em cadastro (Ex.8, cenário sem `extra="forbid"`) | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | **7.5** | High | Alto — permitiria escalonamento de privilégio sem interação humana, base para todos os outros ataques do sistema |
| T-3 | XSS armazenado em `notes` → sessão da recepção (Ex.8) | `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **5.4** | Medium | Médio — exige atacante já autenticado no sistema E vítima abrindo a página específica; ainda assim compromete uma sessão interna |
| — | `ecdsa` 0.19.2 (dependência transitiva de `python-jose`) — Minerva timing attack, PYSEC-2026-1325 / CVE-2024-23342 | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (score publicado pelo advisory) | **7.4** | High | **Baixo na prática, apesar do score** — a aplicação assina JWT com HS256 (HMAC simétrico); o caminho de código vulnerável (assinatura/derivação ECDSA em curva P-256) nunca é exercido. Mantido monitorado, não bloqueia o gate (ver critério abaixo) |

A priorização real de correção seguiu **T-2 > T-4 > T-3**, mesmo T-2 e
T-4 tendo scores próximos, porque o critério de negócio (dado de saúde
exposto de forma direta e trivial de explorar, sem interação de
terceiros) pesa mais que a diferença de 0.6 pontos entre os dois no
CVSS puro.

## 3. Security gate — critério de bloqueio (definido e justificado)

**Critério adotado:** o pipeline **bloqueia o merge** quando:
1. Bandit reporta qualquer achado de severidade **High** com confiança
   **Medium ou High**; ou
2. `pip-audit` encontra uma vulnerabilidade com **CVSS ≥ 7.0** em uma
   dependência **cujo caminho de código vulnerável é alcançável** pela
   aplicação; ou
3. Qualquer teste da suíte de segurança (`tests/test_authorization.py`,
   `tests/test_security_fixes.py`) falhar.

**Por que CVSS ≥ 7.0 e não qualquer CVE:** um dependency scanner honesto
encontra dezenas de CVEs de baixo/médio impacto em qualquer árvore de
dependências real; bloquear o pipeline para todas elas treina o time a
ignorar o gate ("security fatigue"). O corte em 7.0 (High/Critical)
mantém o gate acionado só para o que exige ação imediata.

**Por que "caminho de código alcançável" é parte do critério, não só o
score:** o próprio caso do `ecdsa` (CVSS 7.4) prova a necessidade dessa
cláusula — bloquear automaticamente destruiria a produtividade do time
por uma CVE que não afeta este sistema (não usamos ES256), enquanto uma
regra puramente numérica trataria os dois casos como equivalentes. Essa
exceção é documentada explicitamente no workflow (ver
`.github/workflows/security.yml`, job `dependency-scan`), não decidida
silenciosamente — outra pessoa revisando o pipeline vê o motivo exato.

**Critério que NUNCA tem exceção:** qualquer achado **Critical (CVSS ≥
9.0)** bloqueia sempre, independentemente de "caminho alcançável" — o
risco de julgar errado a alcançabilidade não compensa a economia de
tempo quando o placar já está no topo da escala.

## 4. Testes de autorização expandidos (rastreáveis ao threat model)

O teste único do Exercício 6 (`test_non_admin_blocked_from_admin_route`)
foi expandido em `tests/test_authorization.py` para cobrir os demais
vetores mapeados no threat model do Exercício 4:

| Teste | Ameaça (STRIDE / ID) coberta |
|---|---|
| `test_non_admin_blocked_from_admin_route` | Elevation of Privilege — RBAC básico (Ex.6) |
| `test_bola_blocked_on_get` / `_on_update` / `_on_list` | T-2 — Tampering / Information Disclosure (BOLA) |
| `test_privilege_escalation_via_mass_assignment_blocked` | T-4 — Elevation of Privilege (mass assignment) |
| `test_professional_cannot_create_appointment_for_colleague` | T-4 — variante de mass assignment na criação |
| `test_m2m_token_cannot_access_human_routes` | T-5 — Elevation of Privilege (escopo M2M) |
| `test_m2m_wrong_secret_rejected` | T-1 — Spoofing (M2M) |
| `test_unauthenticated_request_rejected` | Controle base de autenticação |
| `test_stored_xss_payload_rejected_at_input` | T-3 — Injection (defesa em profundidade) |

Rodar: `pytest tests/test_authorization.py -v` — os 9 testes acima
passam de forma determinística (banco SQLite em memória, isolado por
teste via `tests/conftest.py`).
