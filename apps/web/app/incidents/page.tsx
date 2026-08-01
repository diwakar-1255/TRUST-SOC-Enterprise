"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import Shell from "@/components/Shell";
import { OperationsSummary, SecurityIncident, formatDate, request } from "@/lib/api";

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [summary, setSummary] = useState<OperationsSummary | null>(null);
  const [status, setStatus] = useState("all");
  const [error, setError] = useState("");
  const router = useRouter();

  const load = useCallback(async () => {
    const query = status === "all" ? "" : `?status=${status}`;
    try {
      const [rows, counts] = await Promise.all([
        request<SecurityIncident[]>(`/operations/incidents${query}`),
        request<OperationsSummary>("/operations/summary"),
      ]);
      setIncidents(rows);
      setSummary(counts);
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load incidents");
    }
  }, [status]);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) { router.push("/login"); return; }
    void load();
    const timer = window.setInterval(() => void load(), 15000);
    return () => window.clearInterval(timer);
  }, [load, router]);

  return (
    <Shell>
      <div className="header">
        <div><div className="eyebrow">Incident response</div><h1>Security incidents</h1><p className="subtitle">Prioritized investigation cases with SLA tracking and response state.</p></div>
        <select className="select-input" value={status} onChange={(event) => setStatus(event.target.value)}>
          {['all','open','acknowledged','investigating','contained','resolved','closed'].map((item) => <option key={item}>{item}</option>)}
        </select>
      </div>
      {error && <div className="card error">{error}</div>}
      <div className="grid operations-grid">
        <IncidentMetric label="Open" value={summary?.open_incidents ?? 0} />
        <IncidentMetric label="Investigating" value={summary?.investigating_incidents ?? 0} />
        <IncidentMetric label="Critical" value={summary?.critical_incidents ?? 0} />
        <IncidentMetric label="Acknowledged" value={summary?.acknowledged_incidents ?? 0} />
      </div>
      <section className="card section">
        <div className="table-wrap"><table>
          <thead><tr><th>Case</th><th>Severity</th><th>Incident</th><th>Assets</th><th>Events</th><th>Status</th><th>SLA due</th></tr></thead>
          <tbody>{incidents.length ? incidents.map((incident) => (
            <tr key={incident.id}>
              <td><Link className="table-link" href={`/incidents/${incident.id}`}><strong>{incident.case_number}</strong></Link><div className="table-subtitle">{incident.priority} · Risk {incident.risk_score}</div></td>
              <td><span className={`badge ${incident.severity}`}>{incident.severity}</span></td>
              <td>{incident.title}<div className="table-subtitle">Updated {formatDate(incident.updated_at)}</div></td>
              <td>{incident.affected_assets.join(", ") || "—"}</td>
              <td>{incident.occurrence_count}</td>
              <td><span className={`badge ${incident.status}`}>{incident.status}</span></td>
              <td>{formatDate(incident.sla_due_at)}</td>
            </tr>
          )) : <tr><td colSpan={7} className="empty-state">No incidents match this filter.</td></tr>}</tbody>
        </table></div>
      </section>
    </Shell>
  );
}

function IncidentMetric({ label, value }: { label: string; value: number }) {
  return <div className="card queue-metric"><div className="metric-small">{value}</div><div className="label">{label}</div></div>;
}
