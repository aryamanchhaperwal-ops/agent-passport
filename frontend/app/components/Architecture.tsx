export default function Architecture() {
  const stages = [
    { title: "HUMAN", note: "root authority signs the first credential" },
    { title: "AGENT A", note: "planner — delegates a narrowed subset" },
    { title: "AGENT B", note: "specialist — delegates again, still narrowing" },
    { title: "AGENT C", note: "worker — can only propose a tool call" },
  ];
  const checks = [
    { title: "Identity", note: "requester is the credential's subject" },
    { title: "Delegation", note: "every hop links to a valid parent" },
    { title: "Signature", note: "Ed25519 over canonical bytes" },
    { title: "Scope", note: "requested capability ⊆ delegated authority" },
    { title: "Expiry / Revocation", note: "validity windows and the revocation registry" },
  ];
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">Architecture</h2>
      <p className="mt-1 text-sm text-slate-600">
        AI PROPOSES. SECURITY VERIFIES. SYSTEM EXECUTES. Authority flows downward and can
        only narrow; the gateway is the single path to any tool.
      </p>

      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <div className="space-y-2">
          {stages.map((s, i) => (
            <div key={s.title}>
              <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2">
                <div className="text-sm font-bold text-slate-800">{s.title}</div>
                <div className="text-xs text-slate-500">{s.note}</div>
              </div>
              {i < stages.length - 1 && <div className="ml-6 h-3 w-px bg-slate-300" />}
            </div>
          ))}
          <div className="rounded-lg border border-indigo-300 bg-indigo-50 px-3 py-2">
            <div className="text-sm font-bold text-indigo-900">AGENTPASSPORT SECURITY GATEWAY</div>
            <div className="text-xs text-indigo-700">the only path from a proposal to a tool</div>
          </div>
        </div>

        <div className="space-y-2">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Verification stages (deterministic code, no LLM)
          </div>
          {checks.map((c) => (
            <div key={c.title} className="rounded-lg border border-slate-200 px-3 py-2">
              <div className="text-sm font-semibold text-slate-800">{c.title}</div>
              <div className="text-xs text-slate-500">{c.note}</div>
            </div>
          ))}
          <div className="grid grid-cols-2 gap-2 pt-1">
            <div className="rounded-lg bg-emerald-50 px-3 py-2 text-center ring-1 ring-emerald-200">
              <div className="text-sm font-bold text-emerald-700">ALLOW → TOOL</div>
            </div>
            <div className="rounded-lg bg-red-50 px-3 py-2 text-center ring-1 ring-red-200">
              <div className="text-sm font-bold text-red-700">DENY → BLOCKED</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
