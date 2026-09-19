"use client";

import { AgentInfo, ChainLink, ROLE_LABELS } from "@/lib/api";

function StatusPill({ status }: { status: string }) {
  const styles: Record<string, string> = {
    ACTIVE: "bg-emerald-100 text-emerald-800 ring-emerald-600/20",
    REVOKED: "bg-amber-100 text-amber-800 ring-amber-600/20",
    BLOCKED: "bg-red-100 text-red-800 ring-red-600/20",
  };
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ring-1 ring-inset ${styles[status] ?? "bg-slate-100 text-slate-700 ring-slate-500/20"}`}>
      {status}
    </span>
  );
}

function Node({
  agent,
  label,
}: {
  agent: AgentInfo | null;
  label: string;
}) {
  const status = agent?.status ?? "ACTIVE";
  const revoked = status === "REVOKED" || status === "BLOCKED";
  return (
    <div className={`flex-1 rounded-xl border bg-white p-4 shadow-sm transition ${revoked ? "border-red-300" : "border-slate-200"}`}>
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
          <div className="text-base font-semibold text-slate-900">{agent?.agent_id ?? label.toLowerCase()}</div>
        </div>
        <StatusPill status={status} />
      </div>
      <dl className="mt-3 space-y-1 text-sm">
        <div className="flex justify-between gap-2">
          <dt className="text-slate-500">Role</dt>
          <dd className="font-medium text-slate-800">{ROLE_LABELS[agent?.role ?? ""] ?? "—"}</dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-slate-500">Delegated scope</dt>
          <dd className="text-right font-mono text-[13px] font-medium text-indigo-700">
            {agent?.effective_scopes.join(", ") || "—"}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function Arrow({ link }: { link?: ChainLink }) {
  const bad = link && (!link.valid || link.revoked);
  return (
    <div className="flex flex-col items-center py-1" aria-hidden>
      <div className={`h-6 w-px ${bad ? "bg-red-400" : "bg-emerald-400"}`} />
      <div className={`text-[10px] ${bad ? "text-red-500" : "text-emerald-600"}`}>▼</div>
      <div className={`h-6 w-px ${bad ? "bg-red-400" : "bg-emerald-400"}`} />
    </div>
  );
}

export default function DelegationChain({
  agents,
  links,
  chainSummary,
}: {
  agents: AgentInfo[];
  links: ChainLink[];
  chainSummary: { human_scopes: string[]; executor_scopes: string[]; executor_status: string };
}) {
  const byId = new Map(agents.map((a) => [a.agent_id, a]));
  const revokedLink = links.find((l) => l.revoked);

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <header className="mb-4 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">Delegation chain</h2>
        {revokedLink && (
          <span className="rounded-full bg-red-100 px-3 py-1 text-xs font-semibold text-red-700">
            {revokedLink.to} delegation revoked — downstream blocked
          </span>
        )}
      </header>

      <div className="flex flex-col items-stretch gap-1 lg:flex-row lg:items-center">
        <div className="flex-1 rounded-xl border border-slate-200 bg-slate-50 p-4">
          <div className="text-xs font-medium uppercase tracking-wide text-slate-500">Root authority</div>
          <div className="text-base font-semibold text-slate-900">Human</div>
          <div className="mt-2 font-mono text-[13px] text-indigo-700">{chainSummary.human_scopes.join(", ")}</div>
        </div>
        <Arrow link={links[0]} />
        <Node agent={byId.get("planner") ?? null} label="Agent A" />
        <Arrow link={links[1]} />
        <Node agent={byId.get("specialist") ?? null} label="Agent B" />
        <Arrow link={links[2]} />
        <Node agent={byId.get("executor") ?? null} label="Agent C" />
      </div>

      <div className="mt-3 flex flex-col items-center">
        <Arrow />
        <div className="w-full rounded-xl border border-indigo-200 bg-indigo-50 p-4 text-center">
          <div className="text-sm font-semibold text-indigo-900">Security Gateway</div>
          <div className="text-xs text-indigo-700">every request verified — signature · chain · scope · expiry · revocation</div>
        </div>
        <Arrow />
        <div className="w-full rounded-xl border border-slate-200 bg-white p-3 text-center text-sm font-medium text-slate-700">
          Simulated local tools
        </div>
      </div>

      <p className="mt-3 text-xs text-slate-500">
        Authority only narrows: Agent C holds <span className="font-mono">{chainSummary.executor_scopes.join(", ")}</span> —
        it does not inherit capabilities granted higher in the chain.
      </p>
    </section>
  );
}
