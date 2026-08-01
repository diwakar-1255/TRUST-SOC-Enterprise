"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import Shell from "@/components/Shell";
import {
  HoneypotIntegrationStatus,
  IntegrationStatus,
  formatDate,
  request,
} from "@/lib/api";

export default function IntegrationsPage() {
  const [wazuh, setWazuh] = useState<IntegrationStatus | null>(null);
  const [honeypot, setHoneypot] = useState<HoneypotIntegrationStatus | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [syncing, setSyncing] = useState<string | null>(null);
  const router = useRouter();

  const load = useCallback(async () => {
    try {
      const [wazuhStatus, honeypotStatus] = await Promise.all([
        request<IntegrationStatus>("/integrations/wazuh/status"),
        request<HoneypotIntegrationStatus>("/integrations/honeypot/status"),
      ]);
      setWazuh(wazuhStatus);
      setHoneypot(honeypotStatus);
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load integrations");
    }
  }, []);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    void load();
  }, [load, router]);

  async function sync(name: "wazuh" | "honeypot") {
    setSyncing(name);
    setMessage("");
    setError("");
    try {
      const result = await request<Record<string, unknown>>(`/integrations/${name}/sync`, {
        method: "POST",
      });
      setMessage(`${name === "wazuh" ? "Wazuh" : "Honeypot"} synchronization completed: ${JSON.stringify(result)}`);
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Synchronization failed");
    } finally {
      setSyncing(null);
    }
  }

  return (
    <Shell>
      <div className="header">
        <div>
          <div className="eyebrow">Platform connectivity</div>
          <h1>Security integrations</h1>
          <p className="subtitle">
            Manage endpoint detection and deployed external-threat intelligence connectors.
          </p>
        </div>
      </div>

      {error && <div className="card error">{error}</div>}
      {message && <div className="card success-message">{message}</div>}

      <IntegrationCard
        logo="W"
        title="Wazuh 4.14"
        description="Endpoint agents, alerts, MITRE mappings and health state."
        status={wazuh?.status ?? "unknown"}
        stats={[
          ["Manager API", wazuh?.manager_connected ? "Online" : "Offline"],
          ["Indexer API", wazuh?.indexer_connected ? "Online" : "Offline"],
          ["Agents", wazuh?.synchronized_agents ?? 0],
          ["Alerts stored", wazuh?.synchronized_alerts ?? 0],
        ]}
        lastSync={wazuh?.last_success_at ?? null}
        error={wazuh?.last_error ?? null}
        syncing={syncing === "wazuh"}
        onSync={() => void sync("wazuh")}
        consoleUrl="https://localhost"
      />

      <IntegrationCard
        logo="H"
        title="Deployed Honeypot SOC"
        description="Live SSH, HTTP, HTTPS and FTP attacker intelligence from Azure."
        status={honeypot?.status ?? "unknown"}
        stats={[
          ["API", honeypot?.api_connected ? "Online" : "Offline"],
          ["Attack events", honeypot?.total_events ?? 0],
          ["Attackers", honeypot?.total_attackers ?? 0],
          ["SOC alerts", honeypot?.total_alerts ?? 0],
        ]}
        lastSync={honeypot?.last_success_at ?? null}
        error={honeypot?.last_error ?? null}
        syncing={syncing === "honeypot"}
        onSync={() => void sync("honeypot")}
        consoleUrl={honeypot?.grafana_url}
      />
    </Shell>
  );
}

function IntegrationCard({
  logo,
  title,
  description,
  status,
  stats,
  lastSync,
  error,
  syncing,
  onSync,
  consoleUrl,
}: {
  logo: string;
  title: string;
  description: string;
  status: string;
  stats: [string, string | number][];
  lastSync: string | null;
  error: string | null;
  syncing: boolean;
  onSync: () => void;
  consoleUrl?: string;
}) {
  return (
    <section className="card integration-panel section">
      <div className="integration-logo">{logo}</div>
      <div className="integration-body">
        <div className="integration-title">
          <div>
            <h2>{title}</h2>
            <p>{description}</p>
          </div>
          <span className={`status-dot ${status}`}>{status}</span>
        </div>
        <div className="integration-stats">
          {stats.map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <strong>{typeof value === "number" ? value.toLocaleString() : value}</strong>
            </div>
          ))}
        </div>
        <div className="integration-footer">
          <span>Last successful sync: {formatDate(lastSync)}</span>
          <div className="header-actions">
            {consoleUrl && (
              <a className="button-link" href={consoleUrl} target="_blank" rel="noreferrer">
                Open console
              </a>
            )}
            <button className="primary compact" onClick={onSync} disabled={syncing}>
              {syncing ? "Synchronizing…" : "Synchronize now"}
            </button>
          </div>
        </div>
        {error && <div className="inline-error">{error}</div>}
      </div>
    </section>
  );
}
