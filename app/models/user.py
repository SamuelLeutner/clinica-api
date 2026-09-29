from datetime import datetime, timezone

from sqlmodel import Field, SQLModel

from app.models.enums import UserRole


class User(SQLModel, table=True):
    """Conta de acesso ao sistema. A senha nunca é armazenada em texto
    plano — apenas o hash bcrypt (Exercício 6). `mfa_secret` guarda o
    segredo do MFA simulado (ver app/security/auth.py); nunca é exposto
    em nenhum response model.
    """

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True, max_length=64)
    hashed_password: str
    role: UserRole = Field(index=True)
    is_active: bool = Field(default=True)

    # MFA simulado — obrigatório para contas administrativas.
    mfa_enabled: bool = Field(default=False)
    mfa_secret: str | None = Field(default=None)

    # Vincula a conta de login a um registro de profissional de saúde,
    # usado para verificação de ownership sobre as consultas.
    professional_id: int | None = Field(default=None, foreign_key="healthprofessional.id")

    # Campos de auditoria interna — NUNCA expostos em response_model.
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
