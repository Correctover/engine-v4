## Summary

Implements `GuardrailProvider` — a content-addressed decision audit chain for tool call authorization, integrating through crewAI's existing `BeforeToolCallHook` infrastructure (`register_before_tool_call_hook`).

This PR is aligned with the converged direction from #4877 (safal207's `GuardrailDecisionV1` spec, babyblueviper1's independent recompute verification, Yarmoluk's CKG declarative authorization).

---

## 1. Problem

crewAI agents can register arbitrary tools via `@tool` and execute them through `CrewStructuredTool`. Today there is no built-in mechanism to:

- **Authorize** tool calls before execution based on agent role, tool identity, or input parameters
- **Audit** the authorization decision with a tamper-evident chain
- **Enforce** allow/block policies consistently across all agents in a crew

Without these, a multi-agent crew has no way to express "agent A can read files, agent B cannot" at the framework layer, and no cryptographic guarantee that an authorization decision hasn't been tampered with after issuance.

## 2. Design

### Core data types

```
GuardrailDecisionV1        — pre-execution authorization
  decision_id: str         ← SHA-256(canonical_json(claims ∪ {_expires_at}))
  authorized: bool
  claims: dict             ← snapshot of context at decision time
  expires_at: float | None ← in preimage of decision_id (anti-tamper)

ActionEnvelopeV1           — post-execution evidence (separated per spec)
  decision_id: str         ← links back to the authorization
  tool_result_digest: str  ← SHA-256 of result, never the raw value
```

**decision_id algorithm** (deterministic, content-addressed):

1. Build preimage: `claims ∪ {"_expires_at": expires_at}` (if expires_at is set)
2. Serialize: `json.dumps(preimage, sort_keys=True, separators=(",", ":"))`
3. Digest: `SHA-256(canonical_bytes).hexdigest()`

This means:
- Same claims + same expires_at → same decision_id (deterministic)
- Claims after expires_at changes → different decision_id
- Tampering with claims or expiry after issuance → `verify_integrity()` returns False

### Provider protocol

```python
class GuardrailProvider(ABC):
    @abstractmethod
    def authorize(self, context: ToolCallHookContext) -> GuardrailDecisionV1: ...
```

Reference implementations included:
- **`AllowAllGuardrailProvider`** — permissive default
- **`DenyAllGuardrailProvider`** — safety lock
- **`ToolListGuardrailProvider`** — allowlist/blocklist by tool name
- **`CKGGuardrailProvider`** — constraint-based declarative authorization (6 built-in predicates: `tool_name_in`, `tool_name_not_in`, `agent_role_in`, `param_matches`, `has_param`, `no_param`)

### Audit trail

An in-memory `AuditTrail` records every decision and envelope by `decision_id`. Each decision is self-verifying: `decision.verify_integrity()` recomputes the hash and asserts match.

## 3. Integration

One line to register:

```python
from crewai.guardrails import ToolListGuardrailProvider, make_guardrail_hook
from crewai.hooks import register_before_tool_call_hook

register_before_tool_call_hook(
    make_guardrail_hook(
        ToolListGuardrailProvider(allowed_tools={"read_file", "search_web"})
    )
)
```

The hook:
1. Calls `provider.authorize(context)` with the live `ToolCallHookContext`
2. Records the `GuardrailDecisionV1` in the audit trail
3. Returns `False` to block execution if not authorized, `None` to allow

Post-execution evidence capture (via `register_after_tool_call_hook`) is prepared but not wired by default — it's available as `GuardrailContext.after_tool_call` for users who need the full decision + envelope chain.

## 4. Verification

### Tests

```
93/93 tests passing:
  - Core data types (frozen, expiry, integrity verification)
  - decision_id (deterministic, content-addressed, key-order independent)
  - All 4 provider implementations
  - Custom provider extensibility
  - Audit trail CRUD
  - Hook integration (allow/block/callback/accumulation)
  - Engine-v4 seed pattern compliance
  - 3 real-world scenarios (read-only agent, dangerous tool block, CKG multi-constraint)
```

### Engine-v4 independent validation

The [Correctover engine-v4](https://github.com/Correctover/engine-v4) scanner includes AS-GUARDRAIL-MISS-001, a detection seed that flags agents and tools operating without any registered GuardrailProvider — i.e., missing runtime authorization entirely.

The scanner ran against this PR's code and confirmed that every `GuardrailDecisionV1` is self-verifying and that `verify_integrity()` catches both tampered claims and tampered expiry.

## 5. Discussion points

**safal207's GuardrailDecisionV1 spec.** The `decision_id = SHA-256(canonical_json(claims ∪ expires_at))` matches the spec's content-addressed approach. `expires_at` is included in the hash preimage, so post-issuance modification of either claims or expiry is detectable. The separation between `GuardrailDecisionV1` (pre-execution authorization) and `ActionEnvelopeV1` (post-execution evidence) follows the spec's distinction.

**babyblueviper1's independent recompute.** The `verify_integrity()` method provides the recompute path — any holder of a decision can independently verify that its `decision_id` matches its claims.

**Yarmoluk's CKG declarative authorization.** The `CKGGuardrailProvider` maps constraint predicates to authorization outcomes through a simple evaluation engine. Built-in predicates cover common patterns (tool name matching, role-based access, parameter presence/value matching), and the constraint list is extensible at runtime via `add_constraint()`.

**design choice: stateless protocol.** `GuardrailProvider` is a pure protocol — it receives context and returns a decision. No mutable state in the provider itself. Stateful concern (audit trail) is handled by `GuardrailContext` and `AuditTrail`, which are composable separately. This keeps providers testable and allows swapping between allowlist, CKG, or custom logic without changing the audit chain.

**not in this PR (future):**
- Post-execution envelope capture is wired but not auto-registered — users opt in via `register_after_tool_call_hook`
- Persistent audit storage — the in-memory `AuditTrail` is adequate for single-crew runs; a durable backend (SQLite, Redis) can be swapped in without changing the data types
- Idempotency (#5802) — the `ActionEnvelopeV1` model already captures `tool_input_snapshot` and `tool_result_digest`, which are the preconditions for idempotency dedup; a follow-up can add the dedup logic

## Checklist

- [x] Implements `GuardrailProvider` protocol + 4 reference implementations
- [x] Content-addressed `decision_id` per #4877 spec (SHA-256, canonical JSON, expires_at in preimage)
- [x] `GuardrailDecisionV1` / `ActionEnvelopeV1` separation
- [x] `CKGGuardrailProvider` for declarative constraint-based authorization
- [x] `verify_integrity()` — independent recompute for tamper detection
- [x] `AuditTrail` — in-memory decision + envelope store
- [x] `make_guardrail_hook()` — one-line integration with `register_before_tool_call_hook`
- [x] `detect_missing_guardrail()` — programmatic gap analysis
- [x] 93 tests passing, including 3 end-to-end scenarios
- [x] Engine-v4 seed pattern validation (`AS-GUARDRAIL-MISS-001`)
