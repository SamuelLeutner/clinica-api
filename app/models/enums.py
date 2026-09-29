from enum import Enum


class UserRole(str, Enum):
    """Os três papéis distinguidos pelo sistema, com permissões diferentes
    sobre os mesmos recursos (base do modelo RBAC do Exercício 6)."""

    RECEPCIONISTA = "recepcionista"
    PROFISSIONAL = "profissional"
    ADMIN = "admin"


class AppointmentStatus(str, Enum):
    """Whitelist fechada de status. Qualquer valor fora deste enum é
    rejeitado automaticamente pelo Pydantic (Exercício 9 — validação
    whitelist), impedindo injeção de estados arbitrários."""

    AGENDADA = "agendada"
    CONFIRMADA = "confirmada"
    CANCELADA = "cancelada"
    CONCLUIDA = "concluida"
