"use client";

/**
 * Typed client for the AgentPassport backend. The UI never computes
 * security facts; every field it renders comes from these responses.
 */

export type AgentInfo = {
  agent_id: string;
  role: string;
  effective_scopes: string[];
  delegation_id: string;
  status: string;
};

export type ChainLink = {
  from: string;
  to: string;
  scopes: string[];
  delegation_id: string;
  valid: boolean;
  revoked: boolean;
};

export type DecisionChecks = {
  identity: boolean;
  chain: boolean;
  signature: boolean;
  revocation: boolean;
  expiry: boolean;
  scope: boolean;
};

export type LastDecision = {
  request: { agent: string; tool: string; authorized_scopes: string[] };
  checks: DecisionChecks;
  decision: string;
  reason: string | null;
  detail: string | null;
  executed: boolean;
  effective_scopes: string[];
  tool_result: { tool: string; ok: boolean; simulated: boolean; data: Record<string, unknown> } | null;
  tamper?: {
    credential_id: string;
    modified_field: string;
    original_scopes: string[];
    tampered_scopes: string[];
    note: string;
  };
};

export type AuditEvent = {
  event_id: string;
  event: string;
  timestamp: string;
  agent: string | null;
  tool: string | null;
  decision: string;
  reason: string | null;
  executed: boolean;
  delegation_id: string | null;
  detail: string | null;
};

export type DemoSnapshot = {
  scenario: string;
  anchor_id: string;
  llm_provider: string;
  gateway_online: boolean;
  agents: AgentInfo[];
  links: ChainLink[];
  chain_summary: { human_scopes: string[]; executor_scopes: string[]; executor_status: string };
  last: LastDecision | null;
  stats: {
    total_decisions: number;
    allowed: number;
    denied: number;
    blocked_actions: number;
    audit_events: number;
  };
  events: AuditEvent[];
};

export type RunResponse = { result: GatewayResult; state: DemoSnapshot; tamper?: LastDecision["tamper"] };

export type GatewayResult = {
  decision: string;
  agent: string | null;
  tool: string | null;
  scope: string | null;
  reason: string | null;
  detail: string | null;
  executed: boolean;
  effective_scopes: string[];
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      detail = body?.detail ?? detail;
    } catch {
      /* keep default */
    }
    throw new Error(`Backend request failed: ${detail}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  state: () => request<DemoSnapshot>("/demo/state"),
  legitimate: () => request<RunResponse>("/demo/legitimate", { method: "POST" }),
  scopeEscalation: () => request<RunResponse>("/demo/attack/scope-escalation", { method: "POST" }),
  signatureTampering: () => request<RunResponse>("/demo/attack/signature-tampering", { method: "POST" }),
  revokeSpecialist: () => request<{ revoked_delegation_id: string; state: DemoSnapshot }>(
    "/demo/revoke-specialist", { method: "POST" },
  ),
  reset: () => request<DemoSnapshot>("/demo/reset", { method: "POST" }),
};

export const ROLE_LABELS: Record<string, string> = {
  planner: "Coordinator",
  specialist: "Delegator",
  executor: "Worker",
};

export function friendlyReason(reason: string | null): string {
  switch (reason) {
    case "UNAUTHORIZED_SCOPE": return "capability outside delegated authority";
    case "SCOPE_ESCALATION": return "delegation grants more than its parent holds";
    case "INVALID_SIGNATURE": return "credential was modified after signing";
    case "REVOKED_DELEGATION": return "an ancestor delegation was revoked";
    case "EXPIRED_DELEGATION": return "delegation validity window elapsed";
    case "SUBJECT_MISMATCH": return "requester is not the credential's subject";
    case "UNKNOWN_ISSUER": return "issuer does not match the trust anchor";
    default: return reason ?? "unknown";
  }
}
