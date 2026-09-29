"""
Rate limiting (Exercício 10).

`/auth/token` recebe um limite bem mais restritivo que o resto da API
porque é o endpoint que já sofreu tentativas de força bruta em testes
anteriores (ver contexto do Exercício 10). O limite vem de Settings
(`LOGIN_RATE_LIMIT`, padrão 5/minute por IP), não hardcoded, para permitir
ajuste por ambiente sem redeploy de código.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
