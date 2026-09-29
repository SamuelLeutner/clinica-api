"""
Cabeçalhos de segurança padrão (Exercício 10).

Motivo de cada um, no contexto desta API:
- HSTS: força HTTPS em todas as requisições subsequentes do navegador;
  crítico porque a API transporta dados de saúde.
- X-Frame-Options: DENY — a página HTML da recepção nunca deve poder ser
  embutida em <iframe> de outro site (mitigação de clickjacking).
- X-Content-Type-Options: nosniff — impede que o navegador tente
  reinterpretar a resposta JSON como HTML/JS por MIME sniffing.
- Referrer-Policy e X-XSS-Protection legada incluídos como reforço barato,
  mesmo com auto-escape do Jinja2 já cobrindo XSS na origem.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "frame-ancestors 'none'; "  # ZAP: "CSP Failure to Define Directive with No Fallback" —
            # frame-ancestors NÃO herda de default-src, precisa ser explícito
            # (reforça o X-Frame-Options acima com o mecanismo mais atual).
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        return response
