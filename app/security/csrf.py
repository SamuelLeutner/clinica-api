"""
Proteção CSRF para o único formulário HTML com efeito colateral do
sistema (`POST /reception/login`) — achado real do OWASP ZAP no
Exercício 13 ("Absence of Anti-CSRF Tokens").

Padrão escolhido: double-submit cookie. Não exige estado no servidor
(sem tabela de sessões pendentes): o servidor gera um token aleatório,
manda ele em um cookie E escondido no formulário; no POST, os dois
precisam bater. Um site de terceiro tentando forjar o POST consegue
fazer o navegador da vítima enviar o cookie automaticamente, mas não
consegue *ler* o valor do cookie para replicar no campo do formulário
(Same-Origin Policy) — por isso o ataque falha mesmo sem o servidor
guardar nada.

Por que isso é suficiente aqui e não precisou de uma lib pronta
(ex.: starlette-csrf): o único endpoint de escrita exposto a um
navegador comum é este login. Todo o resto da API é JSON consumido via
Bearer token em header `Authorization`, que por si só já não é
vulnerável a CSRF (um POST forjado por outro site não consegue anexar
um header Authorization arbitrário).
"""
import hmac
import secrets

from fastapi import HTTPException, status

CSRF_COOKIE_NAME = "csrf_token"


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def verify_csrf_token(cookie_value: str | None, form_value: str | None) -> None:
    if not cookie_value or not form_value or not hmac.compare_digest(cookie_value, form_value):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token CSRF inválido ou ausente")
