"""
Integração M2M do laboratório parceiro (Exercício 7).

Fluxo escolhido: OAuth 2.0 Client Credentials Grant (RFC 6749 §4.4).
Justificativa: não há um usuário humano por trás da chamada — é o sistema
do laboratório se autenticando como ele mesmo para consultar horários
disponíveis. Client Credentials é o fluxo desenhado exatamente para esse
cenário (comunicação máquina-a-máquina, sem UI, sem consentimento de
usuário envolvido), ao contrário de Authorization Code (pensado para
delegar acesso em nome de um usuário que interage com um browser) ou
Device Code (pensado para dispositivos sem browser mas com um humano
presente para autorizar).

O token emitido aqui carrega `scope: "lab:read_availability"` e nenhum
`role` de usuário humano. Isso garante, no nível de claim do JWT — não
apenas em texto de contrato — que mesmo que o token do laboratório seja
comprometido, ele não pode ser usado para acessar rotas de paciente,
profissional ou qualquer coisa fora da consulta de disponibilidade:
`require_scope` verifica explicitamente esse claim, e `get_current_user`
(usado pelas rotas humanas) rejeita qualquer token que tenha esse scope.
"""

import hmac
from datetime import datetime, timedelta, timezone

from fastapi.security import OAuth2
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.openapi.models import OAuthFlows
from fastapi.security.utils import get_authorization_scheme_param
from jose import JWTError, jwt

from app.config import get_settings

settings = get_settings()

LAB_SCOPE = "lab:read_availability"

# Client Credentials (RFC 6749 §4.4) declarado como tal no OpenAPI, com nome próprio
# para não colidir com o esquema de login humano (OAuth2PasswordBearer).
lab_oauth2_scheme = OAuth2(
    flows=OAuthFlows(
        clientCredentials={
            "tokenUrl": "/auth/lab-token",
            "scopes": {LAB_SCOPE: "Consultar horários ocupados"},
        }
    ),
    scheme_name="LabClientCredentials",
    auto_error=False,
)
M2M_TOKEN_EXPIRE_MINUTES = (
    10  # janela curta: token M2M é reemitido a cada consulta em lote
)


def issue_lab_token(client_id: str, client_secret: str) -> str:
    if not (
        hmac.compare_digest(client_id, settings.lab_client_id)
        and hmac.compare_digest(client_secret, settings.lab_client_secret)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client_id ou client_secret inválidos",
        )

    now = datetime.now(timezone.utc)
    payload = {
        "sub": client_id,
        "scope": LAB_SCOPE,
        "iat": now,
        "exp": now + timedelta(minutes=M2M_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(
        payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )


def require_lab_scope(authorization: str | None = Depends(lab_oauth2_scheme)) -> str:
    scheme, token = get_authorization_scheme_param(authorization)
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Não autenticado"
        )
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
        ) from exc

    if payload.get("scope") != LAB_SCOPE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Escopo insuficiente para este recurso",
        )
    return payload["sub"]
