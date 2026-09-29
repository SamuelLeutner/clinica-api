"""
Autorização (Exercícios 6, 8 e 9).

Modelo escolhido: RBAC (Role-Based Access Control) com uma camada extra de
verificação de ownership por recurso para o papel PROFISSIONAL.

Por que RBAC e não ABAC aqui: o sistema tem exatamente três papéis fixos e
conhecidos em tempo de design (recepcionista, profissional, admin), com
regras de permissão que não variam por atributo dinâmico de contexto (hora
do dia, localização, tags de recurso etc.) — o único atributo que importa é
"este profissional é o dono deste registro?", que é um caso de ownership
check, não um critério de ABAC. RBAC + ownership check cobre o requisito
com muito menos complexidade de implementação e auditoria do que ABAC
completo, que só se justificaria se surgissem regras condicionais (ex.:
"profissional só edita consulta até 24h antes do horário"). Autorização
puramente "por recurso" (capability-based) foi descartada por não haver
necessidade de delegação de acesso pontual entre usuários.

Regra de negócio:
- ADMIN: acesso total a todos os recursos.
- RECEPCIONISTA: pode agendar/consultar a agenda de qualquer profissional
  (função de front-desk), mas não edita `notes` clínicas.
- PROFISSIONAL: só acessa/gerencia consultas em que é o profissional
  responsável (ownership) — nunca as de colegas.

Esta é a correção centralizada da falha de BOLA identificada no
Exercício 8: a verificação de ownership vive em UM único lugar
(`verify_appointment_ownership`) e é aplicada como dependency do FastAPI
em toda rota que opera sobre uma consulta específica, em vez de ser
reimplementada (ou esquecida) endpoint a endpoint.
"""
from fastapi import Depends, HTTPException, status
from sqlmodel import Session

from app.database import get_session
from app.models.appointment import Appointment
from app.models.enums import UserRole
from app.models.user import User
from app.security.auth import get_current_user


def require_roles(*allowed_roles: UserRole):
    """Factory de dependency para restringir uma rota a um conjunto de papéis."""

    def _checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Papel '{current_user.role.value}' não tem permissão para esta operação",
            )
        return current_user

    return _checker


def verify_appointment_ownership(
    appointment_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> Appointment:
    """Dependency única para BOLA: busca a consulta pelo ID da URL e garante
    que o usuário autenticado tem direito a ela antes de qualquer handler
    rodar. Profissionais só passam se forem o dono; admin e recepcionista
    sempre passam."""
    appointment = session.get(Appointment, appointment_id)
    if appointment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Consulta não encontrada")

    if current_user.role == UserRole.PROFISSIONAL and appointment.professional_id != current_user.professional_id:
        # 404 (não 403) para não confirmar a um atacante que o ID existe —
        # mitigação adicional contra enumeração de IDs (Exercício 9).
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Consulta não encontrada")

    return appointment
