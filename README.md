# AgentPassport

**Local reference implementation / testbed for runtime authorization of AI-agent delegation.**

**This is a local reference implementation/testbed, not a production authorization system.**
It runs entirely on your machine, contacts no real external systems, and every "tool" is a
local simulation. Nothing here connects to real payments, mail, calendars, or cloud storage.

```
AI AGENT PROPOSES ACTION
        ↓
AGENTPASSPORT SECURITY GATE
        ↓
DETERMINISTIC VERIFICATION   (Ed25519 signatures, delegation chain, scopes,
        ↓                     expiry, revocation — no LLM involvement)
   ALLOW / DENY
        ↓
   TOOL EXECUTION   (DENY => the tool function is NEVER entered)
```

## What it does

A human (the *trust anchor*) grants capabilities to Agent A (planner), who narrows and
re-delegates to Agent B (specialist), who delegates to Agent C (executor):

```
Human  ──signs──▶  Agent A  planner      calendar.read, email.read, files.read
                    │  (signs)           narrowed: calendar.read, files.read
                    ▼
                  Agent B  specialist
                    │  (signs)           narrowed: calendar.read
                    ▼
                  Agent C  executor      may act on calendar.read only
```

Agent C can affect the world only through the SecurityGateway, which re-derives
authorization from the cryptographic chain before any tool runs. C requesting
`calendar.read` → **ALLOW**, tool executes once. C requesting `payments.transfer` →
**DENY**, the payment tool's code is never entered (proven by execute counters).

## Phase 1 architecture (cryptographic core)

```
app/core/
├── identity.py    # Ed25519 identities (cryptography library)
├── delegation.py  # credential issuance, signing, revocation registry
├── verifier.py    # the deterministic chain verifier (the only authority)
├── policy.py      # scope model, attenuation rules, trust anchor
├── models.py      # canonicalization + Pydantic credential models
└── errors.py      # DenyReason taxonomy
```

Layer separation:

| Layer | Responsibility | Implemented by |
|---|---|---|
| **IDENTITY** | who holds which key | `core/identity.py` |
| **DELEGATION** | who granted what, to whom, when | `core/delegation.py`, `core/models.py` |
| **AUTHORIZATION** | is this proposed action covered by a valid chain? | `core/verifier.py` |
| **POLICY** | what capabilities exist; how they attenuate | `core/policy.py` |
| **EXECUTION** | actually doing the thing | `app/tools/` + `gateway/` (Phase 2) |

**Cryptographic design.** Credentials are signed over a canonical form (validated model →
`model_dump(mode="json")` → key-sorted, whitespace-free JSON → UTF-8). The signature covers
*every* field including the delegation ID; any tampering — scope, expiry, ID, signature —
breaks verification. The issuer's public key is embedded in each credential. Scope
attenuation (`child ⊆ parent`, no wildcards) and validity inheritance
(`child.expires_at ≤ parent.expires_at`) are enforced both at issuance (clamping) and at
verification (rejection: `SCOPE_ESCALATION` / `EXCEEDS_PARENT_VALIDITY`). Full details and
the verification algorithm are in the module docstrings.

## Phase 2 architecture (agent runtime + security gateway)

```
app/
├── agents/
│   ├── base.py        # agent plumbing over Phase 1 identities
│   ├── planner.py     # Agent A: plan tasks, delegate narrowed authority
│   ├── specialist.py  # Agent B: refine, delegate to C
│   ├── executor.py    # Agent C: propose; execution ONLY via gateway
│   ├── messages.py    # typed Pydantic messages (extra="forbid")
│   └── runtime.py     # composition root: one world, wired once
├── llm/
│   ├── base.py        # provider protocol, fail-closed proposal parser, env config
│   ├── mock.py        # deterministic local provider (default)
│   ├── ollama.py      # local inference (no paid API)
│   └── openrouter.py  # OPTIONAL cloud provider (env key)
├── tools/
│   ├── base.py        # simulated tools with execute counters
│   └── registry.py    # name -> tool; the only tool lookup
├── gateway/
│   └── security_gateway.py  # THE enforcement boundary
└── audit/
    └── events.py      # in-memory append-only audit events
```

**The one authorization path.** There is exactly one:

```
request → SecurityGateway → core.verifier.verify_chain (Phase 1)
        → ALLOW ? registry.execute(tool) : tool never runs
```

The gateway derives the required scope **from the tool registry**, never from the agent's
or LLM's claim; hands the presented chain to the Phase 1 verifier; executes only on ALLOW;
and records one audit event per request. Agents hold no tool objects, no verifier, and no
authorization logic — `AgentRuntime` is the only module that wires an agent to the gateway,
and agents receive tool *names*, never handles.

**The LLM cannot authorize.** Providers return raw text; the only structured output this
layer can produce is an `AgentProposal` (tool name + arguments — descriptive, zero
authority). Malformed, fenced, or nonsensical output parses to `None`. Even a perfectly
formed proposal naming a forbidden tool changes nothing: the gateway re-derives everything
from cryptography. Statements like "Agent C is authorized to transfer money" have no
effect by construction, not by prompting.

## AI-agent flow

1. `AgentRuntime.bootstrap()` creates the human anchor, three Ed25519 identities, the
   Human→A→B→C delegation chain, tools, audit, and the gateway.
2. The planner LLM turns a task into a structured plan (`AgentPlan`).
3. The executor's LLM proposes one tool call (`AgentProposal`).
4. `gateway.authorize_and_execute(agent_id, chain, tool_name, arguments)` decides.
5. ALLOW → the simulated tool runs once and its result is returned; DENY → structured
   denial with a machine-readable reason, tool untouched, event audited.

## Tool gateway

Simulated tools (all local, all return `"simulated": true` metadata): `calendar.read`,
`email.read`, `email.send`, `files.read`, `files.write`, `payments.transfer`. Each declares
the scope it requires; `payments.transfer` returns a fake `SIM-...` transaction id and
moves nothing. Tools count executions (`execute_count`) so tests and demos can *prove* the
boundary: denied calls leave the counter at zero.

Example results:

```json
{"decision": "ALLOW", "agent": "executor", "tool": "calendar.read",
 "scope": "calendar.read", "reason": "AUTHORIZED", "executed": true}

{"decision": "DENY", "agent": "executor", "tool": "payments.transfer",
 "scope": "payments.transfer", "reason": "UNAUTHORIZED_SCOPE", "executed": false}
```

## LLM provider configuration

Copy `.env.example` to `.env` (gitignored) or export the variables:

```bash
LLM_PROVIDER=mock            # mock | ollama | openrouter  (mock = safe default)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
OPENROUTER_API_KEY=          # optional; read from env only, never hard-coded
OPENROUTER_MODEL=
LLM_TIMEOUT_SECONDS=30
```

- **MockProvider** — default. Deterministic, no network, scripted replies for tests.
- **Ollama** — local inference; any connectivity problem raises `LLMUnavailable`.
- **OpenRouter** — optional; refuses to start without `OPENROUTER_API_KEY`.

All providers fail closed: if Ollama is down, OpenRouter is unconfigured, the model times
out, or the output is garbage, the runtime proceeds with **no proposal** — and governance
continues, because authorization never depended on the LLM.

## Running

Requires Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

pytest                        # full suite (Phase 1 + Phase 2)
python demo/basic_chain.py    # Phase 1 crypto demo
python demo/phase2_demo.py    # full agent + gateway demo
python demo/attack_demo.py    # six attack scenarios

uvicorn app.main:app --port 8000   # localhost only
```

API endpoints:

- `GET  /health` — liveness
- `POST /verify` — Phase 1 verifier over a submitted chain
- `POST /agents/run` — plan a task and route the proposal through the gateway
- `POST /tools/execute` — tool request; ALWAYS via the SecurityGateway (no direct
  execution endpoint exists anywhere)
- `GET  /audit` — the in-memory audit log
- `GET  /agents` — public agent descriptions
- `GET  /security/status` — composition + enforcement status

## Attack scenarios (all demonstrated in `demo/attack_demo.py` and tests)

| # | Attack | Expected | Physical proof |
|---|---|---|---|
| 1 | Privilege escalation (C → payments.transfer) | DENY / UNAUTHORIZED_SCOPE | payments executed 0 times |
| 2 | Forged delegation (modified signature) | DENY / INVALID_SIGNATURE | tool never ran |
| 3 | Compromised intermediary (B grants what it lacks) | DENY / SCOPE_ESCALATION | tool never ran |
| 4 | Revocation (revoke B) | DENY / REVOKED_DELEGATION | tool never ran |
| 5 | Expired authority | DENY / EXPIRED_DELEGATION | tool never ran |
| 6 | LLM social engineering / prompt injection | proposal unusable or DENY | tool never ran |

## Threat model

Defended (Phase 1 mechanisms, enforced at the gateway):

- **Compromised intermediary** — attenuation + validity inheritance at every hop; a
  malicious B can sign an over-broad credential but the verifier rejects its use.
- **Malicious child** — requester must be the leaf subject; requested scope must be in the
  leaf's effective set.
- **Forged / modified delegation** — every signature checked over canonical bytes; root
  must match the anchor key.
- **Expired authority** — every credential's window checked; effective expiry is
  monotonically non-increasing from root to leaf.
- **Revoked authority** — registry consulted for every credential in the chain.
- **Broken chains** — full parent-link validation; depth bounded.
- **LLM overreach / injection** — LLM output is inert by construction; the gateway derives
  scope and authorization without it; unparseable output means no proposal (fail closed).
- **Direct tool bypass** — agents hold no tool objects; `ToolRegistry.execute` is reachable
  only through the gateway; the API exposes no unguarded execution route.

## Security limitations

- Local testbed: **no API authentication, no TLS, no persistence**; revocation and audit
  die with the process. Do not expose beyond localhost.
- The runtime is the credential custodian: it hands each agent's chain to the gateway on
  the agent's behalf. A deployment must add proof-of-possession (requester signs the
  request with the leaf key) so a stolen agent_id alone is useless.
- `/verify` accepts a client-supplied `now` (prototype convenience); a real deployment
  must use its own clock.
- No strict use-once nonce registry; replay protection rests on signature binding.
- LLM prompts are not hardened against producing *parseable* malicious proposals —
  by design they don't need to be, since proposals carry no authority.
- The anchor key is generated at process start; there is no persistent identity layer,
  key rotation, or revocation distribution.
- Nothing here has been audited. **Not production-ready.**
