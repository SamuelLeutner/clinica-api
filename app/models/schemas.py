"""
Schemas Pydantic separados dos modelos de tabela (SQLModel).

Duas decisões de segurança centrais deste módulo (Exercícios 2 e 9):

1. Todo endpoint de leitura usa um schema "*Read" explícito como
   response_model. Nunca devolvemos o SQLModel de tabela diretamente:
   se devolvêssemos, qualquer coluna nova adicionada no futuro (ex.: um
   campo de auditoria) vazaria automaticamente na API sem ninguém notar.
   response_model funciona como uma allowlist de campos expostos — o
   oposto de confiar em "esquecer de remover" um campo sensível.

2. Todo schema de entrada ("*Create"/"*Update") define
   `model_config = ConfigDict(extra="forbid")`. Isso rejeita com 422
   qualquer campo não declarado no corpo da requisição — por exemplo,
   um client tentando injetar `"role": "admin"` num payload de cadastro,
   ou `"created_by_user_id": 1` para forjar autoria.
"""
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from app.models.enums import AppointmentStatus, UserRole

# Regexes usados como whitelist de formato (Exercício 9).
_CPF_RE = r"^\d{11}$"
_PHONE_RE = r"^\+?\d{8,15}$"
_LICENSE_RE = r"^[A-Z]{2,4}-[A-Z]{2}-\d{4,8}$"  # ex.: CRM-SP-123456


# --------------------------------------------------------------------------
# Paciente
# --------------------------------------------------------------------------
class PatientCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str
    cpf: str
    birth_date: date
    phone: str
    email: EmailStr

    @field_validator("full_name")
    @classmethod
    def name_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not (2 <= len(v) <= 120):
            raise ValueError("full_name deve ter entre 2 e 120 caracteres")
        return v

    @field_validator("cpf")
    @classmethod
    def cpf_whitelist(cls, v: str) -> str:
        import re

        v = re.sub(r"\D", "", v)
        if not re.fullmatch(_CPF_RE, v):
            raise ValueError("cpf deve conter exatamente 11 dígitos numéricos")
        return v

    @field_validator("phone")
    @classmethod
    def phone_whitelist(cls, v: str) -> str:
        import re

        if not re.fullmatch(_PHONE_RE, v):
            raise ValueError("phone inválido — formato esperado: +5511999999999")
        return v


class PatientRead(BaseModel):
    """Não inclui cpf completo para reduzir exposição desnecessária em
    listagens; o endpoint de detalhe (GET /patients/{id}) pode expor via
    PatientReadDetailed a quem tiver permissão (admin/profissional dono)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    full_name: str
    phone: str
    email: EmailStr
    # cpf e created_by_user_id deliberadamente omitidos aqui.


class PatientReadDetailed(PatientRead):
    cpf: str
    birth_date: date
    # created_by_user_id e created_at continuam de fora: são auditoria interna.


# --------------------------------------------------------------------------
# Profissional de saúde
# --------------------------------------------------------------------------
class ProfessionalCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str
    specialty: str
    license_number: str

    @field_validator("license_number")
    @classmethod
    def license_whitelist(cls, v: str) -> str:
        import re

        if not re.fullmatch(_LICENSE_RE, v.upper()):
            raise ValueError("license_number inválido — formato esperado: CRM-SP-123456")
        return v.upper()


class ProfessionalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    full_name: str
    specialty: str
    license_number: str


# --------------------------------------------------------------------------
# Consulta (appointment) — recurso central
# --------------------------------------------------------------------------
class AppointmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patient_id: int
    professional_id: int
    scheduled_at: datetime
    notes: str = ""

    @field_validator("notes")
    @classmethod
    def notes_length_and_no_markup(cls, v: str) -> str:
        if len(v) > 1000:
            raise ValueError("notes excede 1000 caracteres")
        # Defesa em profundidade: a proteção real contra XSS é o
        # auto-escape do Jinja2 na saída (Exercício 2/9), mas rejeitar
        # marcações óbvias de script na entrada reduz a superfície.
        lowered = v.lower()
        if "<script" in lowered or "javascript:" in lowered or "onerror=" in lowered:
            raise ValueError("notes contém conteúdo não permitido")
        return v


class AppointmentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scheduled_at: datetime | None = None
    status: AppointmentStatus | None = None
    notes: str | None = None


class AppointmentRead(BaseModel):
    """response_model do recurso central. created_by_user_id e updated_at
    ficam de fora deliberadamente — são metadados internos de auditoria,
    não dado de negócio que o cliente precisa ver (Exercício 2)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    patient_id: int
    professional_id: int
    scheduled_at: datetime
    status: AppointmentStatus
    notes: str


# --------------------------------------------------------------------------
# Autenticação
# --------------------------------------------------------------------------
class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    password: str
    role: UserRole
    professional_id: int | None = None

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("password deve ter ao menos 10 caracteres")
        return v


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: UserRole
    mfa_enabled: bool
    # hashed_password e mfa_secret NUNCA aparecem aqui.


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MFAChallenge(BaseModel):
    """Retornado no lugar do token quando a conta exige MFA — o cliente
    deve chamar /auth/mfa/verify com o challenge_id e o código."""

    mfa_required: bool = True
    challenge_id: str


class MFAVerify(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str
    code: str

    @field_validator("code")
    @classmethod
    def code_whitelist(cls, v: str) -> str:
        import re

        if not re.fullmatch(r"^\d{6}$", v):
            raise ValueError("code deve ter exatamente 6 dígitos")
        return v
