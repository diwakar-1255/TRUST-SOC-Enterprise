"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";

import Shell from "@/components/Shell";
import { AlertGroupDetail, formatDate, request } from "@/lib/api";

export default function AlertDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const [group, setGroup] = useState<AlertGroupDetail | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    request<AlertGroupDetail>(`/operations/alert-groups/${params.id}`)
      .then(setGroup)
      .catch((caught) => setError(caught instanceof Error ? caught.message : "Unable to load alert"));
  }, [params.id, router]);

  return (
    <Shell>
      <div className="header">
        <div>
          <div className="eyebrow">Correlated detection</div>
          <h1>{group?.title ?? "Loading alert group"}</h1>
          <p className="subtitle">Immutable raw alerts remain available below the aggregated SOC record.</p>
        </div>
        <Link className="secondary" href="/alerts">Back to queue</Link>
      </div>
      {error && <div className="card error">{error}</div>}
      {group && (
        <>
          <div className="grid detail-metrics">
            <Detail label="Risk score" value={`${group.risk_score}/100`} />
            <Detail label="Occurrences" value={group.occurrence_count} />
            <Detail label="Severity" value={group.severity} />
            <Detail label="Status" value={group.status} />
            <Detail label="First seen" value={formatDate(group.first_seen)} />
            <Detail label="Last seen" value={formatDate(group.last_seen)} />
          </div>
          <section className="card section">
            <h2>Detection context</h2>
            <dl className="detail-list wide">
              <div><dt>Rule</dt><dd>{group.rule_id} · Level {group.max_rule_level}</dd></div>
              <div><dt>Endpoint</dt><dd>{group.agent_name ?? "Wazuh manager"}</dd></div>
              <div><dt>MITRE ATT&amp;CK</dt><dd>{group.mitre_techniques.join(", ") || "—"}</dd></div>
              <div><dt>Groups</dt><dd>{group.groups.join(", ") || "—"}</dd></div>
              <div><dt>Suppression</dt><dd>{group.suppression_reason || "Not suppressed"}</dd></div>
            </dl>
          </section>
          <section className="card section">
            <h2>Raw Wazuh alerts ({group.raw_alerts.length})</h2>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Event</th><th>Status</th></tr></thead>
                <tbody>{group.raw_alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>{formatDate(alert.event_timestamp)}</td>
                    <td><span className={`badge ${alert.severity}`}>{alert.severity}</span></td>
                    <td>{alert.rule_id}</td>
                    <td>{alert.title}</td>
                    <td>{alert.status}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </Shell>
  );
}

function Detail({ label, value }: { label: string; value: string | number }) {
  return <div className="card detail-metric"><div className="label">{label}</div><strong>{value}</strong></div>;
}
