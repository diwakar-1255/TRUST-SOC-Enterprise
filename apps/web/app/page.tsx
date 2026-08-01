"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import Shell from "@/components/Shell";
import {
  HoneypotSummary,
  PortalSummary,
  SecurityAlert,
  formatDate,
  request,
} from "@/lib/api";

export default function Dashboard() {
  const [data, setData] = useState<PortalSummary | null>(null);
  const [honeypot, setHoneypot] = useState<HoneypotSummary | null>(null);
  const [error, setError] = useState("");
  const [syncing, setSyncing] = useState(false);
  const router = useRouter();

  const load = useCallback(async () => {
    try {
      const portalData = await request<PortalSummary>("/portal/summary");
      setData(portalData);
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load portal");
      return;
    }

    try {
      setHoneypot(await request<HoneypotSummary>("/portal/honeypot/summary"));
    } catch {
      setHoneypot(null);
    }
  }, []);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    void load();
    const timer = window.setInterval(() => void load(), 15000);
    return () => window.clearInterval(timer);
  }, [load, router]);

  async function syncNow() {
    setSyncing(true);
    try {
      await Promise.allSettled([
        request("/integrations/wazuh/sync", { method: "POST" }),
        request("/integrations/honeypot/sync", { method: "POST" }),
      ]);
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Synchronization failed");
    } finally {
      setSyncing(false);
    }
  }

  return (
    <Shell>
      <div className="header">
        <div>
          <div className="eyebrow">Customer security portal</div>
          <h1>Security operations overview</h1>
          <p className="subtitle">
            Endpoint protection, incident response, telemetry trust and deployed honeypot intelligence.
          </p>
        </div>
        <div className="header-actions">
          <span className={`status-dot ${data?.integration.status ?? "unknown"}`}>
            Wazuh {data?.integration.status ?? "loading"}
          </span>
          <span className={`status-dot ${honeypot?.integration.status ?? "unknown"}`}>
            Honeypot {honeypot?.integration.api_connected ? "online" : "offline"}
          </span>
          <button className="secondary" onClick={syncNow} disabled={syncing}>
            {syncing ? "Synchronizing…" : "Sync all"}
          </button>
        </div>
      </div>

      {error && <div className="card error">{error}</div>}

      <div className="grid metrics-grid">
        <Metric
          label="Telemetry Trust Score"
          value={`${data?.telemetry_trust_score ?? 0}/100`}
          detail="Integrity and source availability"
        />
        <Metric
          label="Protected Assets"
          value={data?.protected_assets ?? 0}
          detail={`${data?.wazuh_agents_active ?? 0} active Wazuh agents`}
        />
        <Metric
          label="Security Events (24h)"
          value={data?.events_24h ?? 0}
          detail={`${data?.grouped_alerts_24h ?? 0} correlated groups · ${data?.alerts_24h ?? 0} raw alerts`}
        />
        <Metric
          label="Critical Sources"
          value={data?.critical_sources ?? 0}
          detail={`${data?.wazuh_agents_disconnected ?? 0} disconnected agents`}
          tone={(data?.critical_sources ?? 0) > 0 ? "critical" : "healthy"}
        />
        <Metric
          label="Telemetry Sources"
          value={data?.telemetry_sources ?? 0}
          detail={`${data?.wazuh_agents_total ?? 0} Wazuh managed`}
        />
        <Metric
          label="Open Incidents"
          value={data?.open_incidents ?? 0}
          detail={`${data?.suppressed_alerts_24h ?? 0} alert groups suppressed`}
        />
      </div>

      <section className="section card external-threat-strip">
        <div>
          <span>Deployed honeypot attacks</span>
          <strong>{(honeypot?.integration.total_events ?? 0).toLocaleString()}</strong>
        </div>
        <div>
          <span>Unique attackers</span>
          <strong>{(honeypot?.integration.total_attackers ?? 0).toLocaleString()}</strong>
        </div>
        <div>
          <span>Critical honeypot alerts</span>
          <strong>{(honeypot?.alerts_by_severity.critical ?? 0).toLocaleString()}</strong>
        </div>
        <div>
          <span>Honeypot connector</span>
          <strong className={honeypot?.integration.api_connected ? "healthy" : "critical"}>
            {honeypot?.integration.api_connected ? "Online" : "Offline"}
          </strong>
        </div>
      </section>

      <div className="grid severity-grid">
        <Severity label="Critical" value={data?.severity.critical ?? 0} tone="critical" />
        <Severity label="High" value={data?.severity.high ?? 0} tone="high" />
        <Severity label="Medium" value={data?.severity.medium ?? 0} tone="medium" />
        <Severity label="Low" value={data?.severity.low ?? 0} tone="low" />
      </div>

      <div className="content-grid">
        <section className="section card">
          <div className="section-heading">
            <div>
              <h2>Recent security alerts</h2>
              <p>Latest normalized Wazuh and honeypot detections.</p>
            </div>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Detection</th>
                  <th>Asset/source</th>
                  <th>MITRE</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {data?.recent_alerts.length ? (
                  data.recent_alerts.map((alert) => <AlertRow key={alert.id} alert={alert} />)
                ) : (
                  <tr>
                    <td colSpan={5} className="empty-state">
                      No synchronized alerts yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="section card integration-card">
          <h2>Integration health</h2>
          <StatusLine label="Wazuh Manager" ok={data?.integration.manager_connected ?? false} />
          <StatusLine label="Wazuh Indexer" ok={data?.integration.indexer_connected ?? false} />
          <StatusLine label="Honeypot API" ok={honeypot?.integration.api_connected ?? false} />
          <StatusLine label="Wazuh alerts" value={data?.integration.synchronized_alerts ?? 0} />
          <StatusLine label="Honeypot alerts" value={honeypot?.integration.synchronized_alerts ?? 0} />
          <div className="integration-time">
            Wazuh sync: {formatDate(data?.integration.last_success_at ?? null)}
          </div>
          <div className="integration-time">
            Honeypot sync: {formatDate(honeypot?.integration.last_success_at ?? null)}
          </div>
        </section>
      </div>

      <section className="section card">
        <h2>MITRE ATT&amp;CK activity</h2>
        <div className="technique-list">
          {data?.mitre_techniques.length ? (
            data.mitre_techniques.map((item) => (
              <div className="technique" key={item.technique}>
                <span>{item.technique}</span>
                <strong>{item.count}</strong>
              </div>
            ))
          ) : (
            <p className="muted">No ATT&amp;CK-mapped alerts in the last 24 hours.</p>
          )}
        </div>
      </section>
    </Shell>
  );
}

function Metric({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: string | number;
  detail: string;
  tone?: string;
}) {
  return (
    <div className={`card metric-card ${tone ?? ""}`}>
      <div className="label">{label}</div>
      <div className="metric">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  );
}

function Severity({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className={`card severity-card ${tone}`}>
      <div className="severity-value">{value}</div>
      <div>{label} alerts</div>
    </div>
  );
}

function AlertRow({ alert }: { alert: SecurityAlert }) {
  return (
    <tr>
      <td>
        <span className={`badge ${alert.severity}`}>{alert.severity}</span>
      </td>
      <td>
        <strong>{alert.title}</strong>
        <div className="table-subtitle">
          {alert.integration ?? "wazuh"} · Rule {alert.rule_id} · Level {alert.rule_level}
        </div>
      </td>
      <td>{alert.agent_name ?? "Security manager"}</td>
      <td>{alert.mitre_techniques.join(", ") || "—"}</td>
      <td>{formatDate(alert.event_timestamp)}</td>
    </tr>
  );
}

function StatusLine({ label, ok, value }: { label: string; ok?: boolean; value?: number }) {
  return (
    <div className="status-line">
      <span>{label}</span>
      {typeof value === "number" ? (
        <strong>{value}</strong>
      ) : (
        <span className={`status-dot ${ok ? "connected" : "error"}`}>
          {ok ? "Online" : "Offline"}
        </span>
      )}
    </div>
  );
}
