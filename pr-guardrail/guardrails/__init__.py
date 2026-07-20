# Guardrails module — content-addressed decision audit chain
#
# This module provides the GuardrailProvider protocol and reference
# implementations for pre-execution tool-call authorization with
# content-addressed decision auditing.
#
# Integration::
#
#     from crewai.guardrails import (
#         GuardrailProvider,
#         ToolListGuardrailProvider,
#         GuardrailContext,
#         make_guardrail_hook,
#     )
#     from crewai.hooks import register_before_tool_call_hook
#
#     guardrail = ToolListGuardrailProvider(allowed_tools={"read_file"})
#     register_before_tool_call_hook(make_guardrail_hook(guardrail))
#
# Spec alignment: crewAI#4877 (GuardrailDecisionV1, ActionEnvelopeV1, CKG)
#                crewAI#5802 (idempotency — future)

from crewai.guardrails.guardrail_provider import (
    AS_GUARDRAIL_MISS_001,
    AS_IDEMPOTENCY_MISS_001,
    ActionEnvelopeV1,
    AllowAllGuardrailProvider,
    AuditTrail,
    CKGGuardrailProvider,
    DenyAllGuardrailProvider,
    GuardrailContext,
    GuardrailDecisionV1,
    GuardrailProvider,
    ToolListGuardrailProvider,
    compute_decision_id,
    detect_missing_guardrail,
    digest_result,
    make_decision_id,
    make_guardrail_hook,
)

__all__ = [
    "GuardrailDecisionV1",
    "ActionEnvelopeV1",
    "compute_decision_id",
    "make_decision_id",
    "digest_result",
    "GuardrailProvider",
    "AllowAllGuardrailProvider",
    "DenyAllGuardrailProvider",
    "ToolListGuardrailProvider",
    "CKGGuardrailProvider",
    "AuditTrail",
    "GuardrailContext",
    "make_guardrail_hook",
    "detect_missing_guardrail",
    "AS_GUARDRAIL_MISS_001",
    "AS_IDEMPOTENCY_MISS_001",
]
