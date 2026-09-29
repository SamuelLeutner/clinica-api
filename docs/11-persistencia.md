# Exercício 11 — Persistência segura

## Migração para SQLModel
`app/database.py` usa `SQLModel`/`SQLAlchemy Core` como engine única de
acesso a dado no projeto inteiro — não existe, em nenhum lugar do código,
uma query montada por f-string, `.format()` ou concatenação de `+` com
input do usuário (verificável por `grep -rn "f\"SELECT\|f'SELECT" app/`,
que não retorna nenhum resultado). Toda leitura/escrita passa por
`select()`, `session.get()` ou `session.add()`, que geram SQL parametrizado
automaticamente via SQLAlchemy Core — o mesmo mecanismo comprovado em
`tests/test_security_fixes.py::test_sql_injection_in_patient_search_has_no_effect`,
que grava um payload clássico de SQLi (`Carlos'; DROP TABLE patient; --`)
como string literal comum, sem nenhum efeito colateral na tabela.

## Injeção de dependência de sessão
`get_session()` (em `app/database.py`) é a única forma de obter uma
`Session` do SQLModel no projeto — injetada via `Depends(get_session)` em
todo endpoint que toca o banco. Isso garante uma sessão por request,
sempre fechada ao final (via `with Session(engine) as session`), sem
vazamento de conexão entre requisições.

## Credenciais via `BaseSettings` + `.env`
`app/config.py` define `Settings(BaseSettings)` lendo `DATABASE_URL`,
`JWT_SECRET_KEY` e `LAB_CLIENT_SECRET` de variáveis de ambiente
carregadas de um arquivo `.env` **nunca versionado** (está em
`.gitignore`). O repositório distribui apenas `.env.example`, com
placeholders — nenhum valor real. Rodar a aplicação sem um `.env`
configurado falha explicitamente na inicialização (campos obrigatórios
sem `default` em `Settings`), em vez de silenciosamente usar um segredo
fraco hardcoded.

## Por que SQLite em desenvolvimento e o que muda em produção
`DATABASE_URL` no `.env.example` aponta para SQLite local — suficiente
para os testes automatizados (que usam SQLite em memória via
`tests/conftest.py`) e para rodar a aplicação localmente sem
infraestrutura extra. Trocar para Postgres em produção é só mudar a
string de conexão (`postgresql+psycopg://...`) — nenhum código de
aplicação muda, porque nenhuma query é específica de um dialeto SQL.
