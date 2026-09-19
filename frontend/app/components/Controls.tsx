"use client";

import { DemoSnapshot } from "@/lib/api";

type Action = "legitimate" | "scope_escalation" | "signature_tampering" | "revoke" | "reset";

const BUTTONS: { action: Action; label: string; primary?: boolean; danger?: boolean }[] = [
  { action: "legitimate", label: "Run Legitimate Request", primary: true },
  { action: "scope_escalation", label: "Run Scope Escalation Attack", danger: true },
  { action: "signature_tampering", label: "Run Credential Tampering Attack", danger: true },
  { action: "revoke", label: "Revoke Agent B" },
  { action: "reset", label: "Reset Demo" },
];

export function DemoControls({
  busy,
  onRun,
}: {
  busy: Action | null;
  onRun: (action: Action) => void;
}) {
  return (
    <section className="rounded-2xl border border-indigo-200 bg-gradient-to-r from-indigo-50 to-white p-5 shadow-sm">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-indigo-900">
          Live security demo
        </h2>
        <span className="text-xs text-indigo-700">
          every button executes through the real Security Gateway
        </span>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {BUTTONS.map(({ action, label, primary, danger }) => (
          <button
            key={action}
            onClick={() => onRun(action)}
            disabled={busy !== null}
            className={`rounded-lg px-4 py-2 text-sm font-semibold shadow-sm transition disabled:cursor-wait disabled:opacity-60 ${
              primary
                ? "bg-indigo-600 text-white hover:bg-indigo-500"
                : danger
                  ? "bg-white text-red-700 ring-1 ring-red-300 hover:bg-red-50"
                  : action === "revoke"
                    ? "bg-white text-amber-700 ring-1 ring-amber-300 hover:bg-amber-50"
                    : "bg-white text-slate-700 ring-1 ring-slate-300 hover:bg-slate-50"
            }`}
          >
            {busy === action ? "Running…" : label}
          </button>
        ))}
      </div>
      <p className="mt-2 text-xs text-slate-500">
        Local, simulated environment. No external systems are contacted; all tools are
        in-process simulations.
      </p>
    </section>
  );
}

export function StatsHeader({ state }: { state: DemoSnapshot }) {
  const stat = (label: string, value: string | number, accent?: string) => (
    <div className="rounded-xl border border-slate-200 bg-white px-4 py-2 shadow-sm">
      <div className="text-[11px] font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`text-lg font-bold ${accent ?? "text-slate-900"}`}>{value}</div>
    </div>
  );
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
      {stat("Gateway", state.gateway_online ? "● ONLINE" : "○ OFFLINE", "text-emerald-600")}
      {stat("Agents", state.agents.length)}
      {stat("Verification", "Ed25519", "text-indigo-600")}
      {stat("Decisions", state.stats.total_decisions)}
      {stat("Allowed", state.stats.allowed, "text-emerald-600")}
      {stat("Blocked", state.stats.blocked_actions, "text-red-600")}
    </div>
  );
}
