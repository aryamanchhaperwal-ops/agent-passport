"use client";

import { AuditEvent, friendlyReason, LastDecision } from "@/lib/api";

const CHECK_ORDER: { key: keyof LastDecision["checks"]; label: string }[] = [
  { key: "identity", label: "IDENTITY" },
  { key: "chain", label: "DELEGATION CHAIN" },
  { key: "signature", label: "SIGNATURE" },
  { key: "revocation", label: "REVOCATION" },
  { key: "expiry", label: "EXPIRY" },
  { key: "scope", label: "SCOPE" },
];

function Check({ ok, label }: { ok: boolean; label: string }) {
  return (
    <li className="flex items-center justify-between rounded-lg border border-slate-100 bg-slate-50 px-3 py-2">
      <span className="text-xs font-semibold tracking-wide text-slate-600">{label}</span>
      <span className={`text-sm font-bold ${ok ? "text-emerald-600" : "text-red-600"}`}>
        {ok ? "✓ verified" : "✕ failed"}
      </span>
    </li>
  );
}

export function DecisionPanel({ last }: { last: LastDecision | null }) {
  if (!last) {
    return (
      <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">Security decision</h2>
        <p className="mt-6 text-center text-sm text-slate-500">
          Run a demo action to see the deterministic verification path.
        </p>
      </section>
    );
  }

  const denied = last.decision === "DENY";

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">Security decision</h2>

      <div className="mt-3 rounded-xl bg-slate-900 p-4 font-mono text-sm text-slate-100">
        <div>
          REQUEST&nbsp;&nbsp;
          <span className="text-indigo-300">{last.request.agent}</span>
          {" → "}
          <span className="text-indigo-300">{last.request.tool}</span>
        </div>
        <div className="mt-1 text-xs text-slate-400">
          authorized: {last.request.authorized_scopes.join(", ")}
        </div>
        {last.tamper && (
          <div className="mt-2 rounded-lg bg-red-950/60 p-2 text-xs text-red-200">
            tamper: {last.tamper.modified_field} {last.tamper.original_scopes.join(",")} →{" "}
            {last.tamper.tampered_scopes.join(",")} — {last.tamper.note}
          </div>
        )}
      </div>

      <ul className="mt-3 space-y-2">
        {CHECK_ORDER.map(({ key, label }) => (
          <Check key={key} ok={last.checks[key]} label={label} />
        ))}
      </ul>

      <div
        className={`decision-in mt-4 rounded-xl p-4 text-center ${
          denied ? "bg-red-50 ring-1 ring-red-200" : "bg-emerald-50 ring-1 ring-emerald-200"
        }`}
      >
        <div className={`text-2xl font-black tracking-tight ${denied ? "text-red-600" : "text-emerald-600"}`}>
          {denied ? "🔴 DENIED" : "🟢 ALLOWED"}
        </div>
        <div className="mt-1 font-mono text-sm font-semibold text-slate-800">{last.reason}</div>
        <div className={`mt-2 text-sm font-medium ${last.executed ? "text-emerald-700" : "text-red-700"}`}>
          Tool execution: {last.executed ? "EXECUTED" : "NOT EXECUTED"}
        </div>
      </div>

      {denied && (
        <div className="mt-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          <div className="font-semibold">WHY WAS THIS REQUEST DENIED?</div>
          <p className="mt-1">
            Agent <span className="font-mono">{last.request.agent}</span> requested{" "}
            <span className="font-mono">{last.request.tool}</span>, but its effective delegated
            authority is <span className="font-mono">{last.request.authorized_scopes.join(", ")}</span>.
            The gateway rejected the request —{" "}
            <span className="font-medium">{friendlyReason(last.reason)}</span> — before any tool code ran.
          </p>
        </div>
      )}
    </section>
  );
}

export function EventFeed({ events }: { events: AuditEvent[] }) {
  const ordered = [...events].reverse();
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">Audit feed</h2>
      <ol className="mt-3 space-y-1.5 font-mono text-xs">
        {ordered.map((e) => {
          const denied = e.decision === "DENY";
          const isDelegation = e.event === "DELEGATION";
          const time = new Date(e.timestamp).toLocaleTimeString([], { hour12: false });
          return (
            <li
              key={e.event_id}
              className={`flex items-start gap-2 rounded-lg border px-3 py-1.5 ${
                denied ? "border-red-200 bg-red-50" : isDelegation ? "border-slate-200 bg-slate-50" : "border-emerald-200 bg-emerald-50"
              }`}
            >
              <span className="text-slate-400">{time}</span>
              <span className="flex-1 text-slate-700">
                {isDelegation
                  ? `${e.agent} delegated authority ${e.detail ?? ""}`
                  : `${e.agent ?? "—"} requested ${e.tool ?? "—"}`}
              </span>
              <span className={`font-bold ${denied ? "text-red-600" : isDelegation ? "text-slate-500" : "text-emerald-600"}`}>
                {isDelegation ? "ISSUED" : e.decision}
              </span>
              {e.reason && e.reason !== "AUTHORIZED" && e.reason !== "DELEGATION_ISSUED" && (
                <span className="text-red-500">{e.reason}</span>
              )}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
