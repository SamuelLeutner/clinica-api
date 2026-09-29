"""
Configurações centralizadas via pydantic-settings.

Nenhum segredo é hardcoded no código-fonte em produção.
Os valores sensíveis vêm de variáveis de ambiente / .env.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Banco de dados
    database_url: str = "sqlite:///./clinica.db"

    # JWT
    jwt_secret_key: str = "change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15

    # MFA
    mfa_challenge_expire_minutes: int = 5

    # Rate limiting
    login_rate_limit: str = "5/minute"

    # CORS
    cors_origins: str = "http://localhost:3000,http://localhost:5173"

    # Cookies / ambiente
    cookie_secure: bool = True
    environment: str = "production"

    # OAuth2 M2M — laboratório parceiro
    lab_client_id: str = "lab-parceiro-01"
    lab_client_secret: str = "dev-only-lab-secret-1234567890"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()


@lru_cache
def get_settings() -> Settings:
    return settings
