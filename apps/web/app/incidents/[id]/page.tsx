"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";

import Shell from "@/components/Shell";
import { IncidentDetail, formatDate, request } from "@/lib/api";

const workflow = ["acknowledged", "investigating", "contained", "resolved", "closed"];

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try { setIncident(await request<IncidentDetail>(`/operations/incidents/${params.id}`)); setError(""); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "Unable to load incident"); }
  }, [params.id]);
  useEffect(() => {
    if (!localStorage.getItem("access_token")) { router.push("/login"); return; }
    void load();
  }, [load, router]);

  async function move(nextStatus: string) {
    setBusy(true);
    try {
      await request(`/operations/incidents/${params.id}`, { method: "PATCH", body: JSON.stringify({ status: nextStatus }) });
      await load();
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Update failed"); }
    finally { setBusy(false); }
  }

  return <Shell>
    <div className="header">
      <div><div className="eyebrow">Incident response case</div><h1>{incident?.case_number ?? "Loading"}</h1><p className="subtitle">{incident?.title}</p></div>
      <Link className="secondary" href="/incidents">Back to incidents</Link>
    </div>
    {error && <div className="card error">{error}</div>}
    {incident && <>
      <div className="workflow-bar">
        {workflow.map((item) => <button key={item} disabled={busy || incident.status === item} className={`workflow-step ${incident.status === item ? "active" : ""}`} onClick={() => move(item)}>{item}</button>)}
      </div>
      <div className="grid detail-metrics">
        <Detail label="Severity" value={incident.severity} />
        <Detail label="Priority" value={incident.priority} />
        <Detail label="Risk" value={`${incident.risk_score}/100`} />
        <Detail label="Occurrences" value={incident.occurrence_count} />
        <Detail label="SLA due" value={formatDate(incident.sla_due_at)} />
        <Detail label="Status" value={incident.status} />
      </div>
      <section className="card section"><h2>Investigation context</h2><dl className="detail-list wide">
        <div><dt>Affected assets</dt><dd>{incident.affected_assets.join(", ") || "—"}</dd></div>
        <div><dt>MITRE techniques</dt><dd>{incident.mitre_techniques.join(", ") || "—"}</dd></div>
        <div><dt>First / last seen</dt><dd>{formatDate(incident.first_seen)} / {formatDate(incident.last_seen)}</dd></div>
        <div><dt>Source</dt><dd>{incident.source}</dd></div>
        <div><dt>Description</dt><dd>{incident.description || "No analyst notes yet."}</dd></div>
      </dl></section>
      <section className="card section"><h2>Linked alert groups</h2><div className="table-wrap"><table>
        <thead><tr><th>Risk</th><th>Detection</th><th>Endpoint</th><th>Occurrences</th><th>Last seen</th></tr></thead>
        <tbody>{incident.alert_groups.map((group) => <tr key={group.id}>
          <td>{group.risk_score}</td><td><Link className="table-link" href={`/alerts/${group.id}`}>{group.title}</Link><div className="table-subtitle">Rule {group.rule_id}</div></td><td>{group.agent_name ?? "Manager"}</td><td>{group.occurrence_count}</td><td>{formatDate(group.last_seen)}</td>
        </tr>)}</tbody>
      </table></div></section>
    </>}
  </Shell>;
}

function Detail({ label, value }: { label: string; value: string | number }) { return <div className="card detail-metric"><div className="label">{label}</div><strong>{value}</strong></div>; }
