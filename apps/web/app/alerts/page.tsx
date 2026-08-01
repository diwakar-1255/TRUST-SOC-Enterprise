"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import Shell from "@/components/Shell";
import { AlertGroup, OperationsSummary, formatDate, request } from "@/lib/api";

const severities = ["all", "critical", "high", "medium", "low"];
const statuses = ["all", "new", "acknowledged", "investigating", "suppressed", "resolved"];

export default function AlertsPage() {
  const [groups, setGroups] = useState<AlertGroup[]>([]);
  const [summary, setSummary] = useState<OperationsSummary | null>(null);
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("new");
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const router = useRouter();

  const load = useCallback(async () => {
    const params = new URLSearchParams();
    if (severity !== "all") params.set("severity", severity);
    if (status !== "all") params.set("status", status);
    if (search.trim()) params.set("search", search.trim());
    try {
      const [rows, operations] = await Promise.all([
        request<AlertGroup[]>(`/operations/alert-groups?${params.toString()}`),
        request<OperationsSummary>("/operations/summary"),
      ]);
      setGroups(rows);
      setSummary(operations);
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load alert queue");
    }
  }, [search, severity, status]);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    void load();
    const timer = window.setInterval(() => void load(), 15000);
    return () => window.clearInterval(timer);
  }, [load, router]);

  async function updateGroup(id: string, nextStatus: string) {
    setBusy(id);
    try {
      await request(`/operations/alert-groups/${id}`, {
        method: "PATCH",
        body: JSON.stringify({
          status: nextStatus,
          suppression_reason:
            nextStatus === "suppressed" ? "Suppressed by SOC analyst from alert queue." : null,
        }),
      });
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Action failed");
    } finally {
      setBusy(null);
    }
  }

  async function createIncident(id: string) {
    setBusy(id);
    try {
      const incident = await request<{ id: string }>(`/operations/alert-groups/${id}/incident`, {
        method: "POST",
        body: JSON.stringify({ description: "Created from the correlated alert queue." }),
      });
      router.push(`/incidents/${incident.id}`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Incident creation failed");
    } finally {
      setBusy(null);
    }
  }

  return (
    <Shell>
      <div className="header">
        <div>
          <div className="eyebrow">Security operations</div>
          <h1>Correlated alert queue</h1>
          <p className="subtitle">
            Wazuh detections are aggregated by rule, endpoint and time window to reduce alert fatigue.
          </p>
        </div>
      </div>

      {error && <div className="card error">{error}</div>}

      <div className="grid operations-grid">
        <QueueMetric label="Unacknowledged" value={summary?.unacknowledged_groups ?? 0} />
        <QueueMetric label="Grouped in 24h" value={summary?.grouped_alerts_24h ?? 0} />
        <QueueMetric label="Suppressed in 24h" value={summary?.suppressed_alerts_24h ?? 0} />
        <QueueMetric label="Open incidents" value={summary?.open_incidents ?? 0} />
      </div>

      <section className="card section">
        <div className="filter-panel">
          <input
            className="search-input"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search rule, detection, or endpoint"
          />
          <div className="filter-row">
            {severities.map((item) => (
              <button
                key={item}
                className={`filter-button ${severity === item ? "selected" : ""}`}
                onClick={() => setSeverity(item)}
              >
                {item}
              </button>
            ))}
          </div>
          <select className="select-input" value={status} onChange={(event) => setStatus(event.target.value)}>
            {statuses.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Risk</th>
                <th>Detection group</th>
                <th>Endpoint</th>
                <th>Occurrences</th>
                <th>Status</th>
                <th>Last seen</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {groups.length ? groups.map((group) => (
                <tr key={group.id}>
                  <td>
                    <div className={`risk-score risk-${riskTone(group.risk_score)}`}>{group.risk_score}</div>
                    <span className={`badge ${group.severity}`}>{group.severity}</span>
                  </td>
                  <td>
                    <Link className="table-link" href={`/alerts/${group.id}`}><strong>{group.title}</strong></Link>
                    <div className="table-subtitle">
                      Rule {group.rule_id} · Level {group.max_rule_level} · Window {formatDate(group.window_start)}
                    </div>
                    <div className="table-subtitle">{group.mitre_techniques.join(", ") || "No MITRE mapping"}</div>
                  </td>
                  <td>{group.agent_name ?? "Wazuh manager"}<div className="table-subtitle">{group.agent_ip ?? "No IP"}</div></td>
                  <td><strong>{group.occurrence_count}</strong></td>
                  <td><span className={`badge ${group.status}`}>{group.status}</span></td>
                  <td>{formatDate(group.last_seen)}</td>
                  <td>
                    <div className="action-stack">
                      {group.status === "new" && (
                        <button className="mini-button" disabled={busy === group.id} onClick={() => updateGroup(group.id, "acknowledged")}>Acknowledge</button>
                      )}
                      {!group.incident_id ? (
                        <button className="mini-button accent" disabled={busy === group.id} onClick={() => createIncident(group.id)}>Create incident</button>
                      ) : (
                        <Link className="mini-button accent" href={`/incidents/${group.incident_id}`}>Open incident</Link>
                      )}
                      {group.status !== "suppressed" && (
                        <button className="mini-button danger" disabled={busy === group.id} onClick={() => updateGroup(group.id, "suppressed")}>Suppress</button>
                      )}
                    </div>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan={7} className="empty-state">No correlated alerts match this filter.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </Shell>
  );
}

function QueueMetric({ label, value }: { label: string; value: number }) {
  return <div className="card queue-metric"><div className="metric-small">{value}</div><div className="label">{label}</div></div>;
}

function riskTone(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  return "low";
}
