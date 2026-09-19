"use client";

import { useCallback, useEffect, useState } from "react";

import Architecture from "./components/Architecture";
import DelegationChain from "./components/DelegationChain";
import { DecisionPanel, EventFeed } from "./components/DecisionPanel";
import { DemoControls, StatsHeader } from "./components/Controls";
import { api, DemoSnapshot, LastDecision } from "@/lib/api";

type Action = "legitimate" | "scope_escalation" | "signature_tampering" | "revoke" | "reset";
type ErrorState = { message: string } | null;

export default function Dashboard() {
  const [state, setState] = useState<DemoSnapshot | null>(null);
  const [last, setLast] = useState<LastDecision | null>(null);
  const [busy, setBusy] = useState<Action | null>(null);
  const [error, setError] = useState<ErrorState>(null);
  const [flowKey, setFlowKey] = useState(0);

  const applyState = useCallback((snapshot: DemoSnapshot) => {
    setState(snapshot);
    setLast(snapshot.last);
    if (snapshot.scenario === "clean") {
      setFlowKey((k) => k + 1); // re-arm flow animation after reset
    }
  }, []);

  const run = useCallback(
    async (action: Action) => {
      setBusy(action);
      setError(null);
      try {
        switch (action) {
          case "legitimate": {
            const body = await api.legitimate();
            applyState(body.state);
            break;
          }
          case "scope_escalation": {
            const body = await api.scopeEscalation();
            applyState(body.state);
            break;
          }
          case "signature_tampering": {
            const body = await api.signatureTampering();
            applyState(body.state);
            break;
          }
          case "revoke": {
            const body = await api.revokeSpecialist();
            applyState(body.state);
            break;
          }
          case "reset": {
            applyState(await api.reset());
            break;
          }
        }
      } catch (e) {
        setError({
          message: e instanceof Error ? e.message : "Unexpected error contacting the backend.",
        });
      } finally {
        setBusy(null);
      }
    },
    [applyState],
  );

  useEffect(() => {
    let cancelled = false;
    api
      .state()
      .then((s) => {
        if (!cancelled) applyState(s);
      })
      .catch((e) => {
        if (!cancelled) {
          setError({
            message:
              e instanceof Error
                ? e.message
                : "Cannot reach the AgentPassport backend.",
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [applyState]);

  if (error && !state) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-20">
        <div className="rounded-2xl border border-red-200 bg-red-50 p-8 text-center">
          <h1 className="text-xl font-bold text-red-800">Backend unavailable</h1>
          <p className="mt-2 text-sm text-red-700">{error.message}</p>
          <p className="mt-4 text-sm text-slate-600">
            Start it with <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono">uvicorn app.main:app --port 8000</code>{" "}
            then reload this page.
          </p>
        </div>
      </main>
    );
  }

  if (!state) {
    return (
      <main className="mx-auto max-w-6xl px-6 py-20 text-center text-sm text-slate-500">
        Connecting to Security Gateway…
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-6xl space-y-4 px-6 py-8">
      <header className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-black tracking-tight text-slate-900">AgentPassport</h1>
            <p className="mt-1 text-sm font-medium text-slate-600">
              Runtime Security Infrastructure for Autonomous AI Agents
            </p>
            <p className="mt-2 font-mono text-xs text-slate-500">
              AI PROPOSES · SECURITY VERIFIES · SYSTEM EXECUTES
            </p>
          </div>
          <div className="text-right text-xs text-slate-500">
            <div className="font-semibold text-emerald-600">● Security Gateway ONLINE</div>
            <div className="mt-1">anchor: {state.anchor_id} · LLM: {state.llm_provider}</div>
          </div>
        </div>
        <div className="mt-4">
          <StatsHeader state={state} />
        </div>
      </header>

      {error && (
        <div className="rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          {error.message}
        </div>
      )}

      <DemoControls busy={busy} onRun={run} />

      <div className="grid gap-4 lg:grid-cols-5">
        <div className="space-y-4 lg:col-span-3">
          <DelegationChain
            key={`chain-${flowKey}-${state.scenario}`}
            agents={state.agents}
            links={state.links}
            chainSummary={state.chain_summary}
          />
          <Architecture />
        </div>
        <div className="space-y-4 lg:col-span-2">
          <DecisionPanel last={last} />
          <EventFeed events={state.events} />
        </div>
      </div>

      <footer className="pb-6 pt-2 text-center text-xs text-slate-400">
        AgentPassport — a working reference implementation and adversarial testbed for
        runtime authorization and delegation security in autonomous AI-agent systems.
        Local simulated environment; developer API at <span className="font-mono">/docs</span>.
      </footer>
    </main>
  );
}
