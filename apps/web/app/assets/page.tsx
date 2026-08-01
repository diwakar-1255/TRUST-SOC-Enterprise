"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import Shell from "@/components/Shell";
import { PortalAsset, formatDate, request } from "@/lib/api";

export default function AssetsPage() {
  const [assets, setAssets] = useState<PortalAsset[]>([]);
  const [error, setError] = useState("");
  const router = useRouter();

  const load = useCallback(async () => {
    try {
      setAssets(await request<PortalAsset[]>("/portal/assets"));
      setError("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load assets");
    }
  }, []);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    void load();
    const timer = window.setInterval(() => void load(), 20000);
    return () => window.clearInterval(timer);
  }, [load, router]);

  return (
    <Shell>
      <div className="header">
        <div>
          <div className="eyebrow">Asset protection</div>
          <h1>Protected assets</h1>
          <p className="subtitle">Endpoint inventory and security telemetry health.</p>
        </div>
        <span className="badge connected">{assets.length} assets</span>
      </div>

      {error && <div className="card error">{error}</div>}

      <div className="asset-grid">
        {assets.map((asset) => (
          <article className="card asset-card" key={asset.id}>
            <div className="asset-title-row">
              <div>
                <h2>{asset.hostname}</h2>
                <p>{asset.operating_system}</p>
              </div>
              <span className={`badge ${asset.source_health}`}>{asset.source_health}</span>
            </div>
            <dl className="detail-list">
              <div><dt>Asset type</dt><dd>{asset.asset_type}</dd></div>
              <div><dt>IP address</dt><dd>{(asset as any).ip_address ?? (asset as any).tags?.ip_address ?? "Not reported"}</dd></div>
              <div><dt>Criticality</dt><dd>{asset.criticality}/5</dd></div>
              <div><dt>Wazuh agent</dt><dd>{asset.wazuh_agent_id ?? "Not linked"}</dd></div>
              <div><dt>Wazuh status</dt><dd>{asset.wazuh_status ?? "Unknown"}</dd></div>
              <div><dt>Telemetry sources</dt><dd>{asset.telemetry_sources}</dd></div>
              <div><dt>Last seen</dt><dd>{formatDate(asset.last_seen)}</dd></div>
            </dl>
          </article>
        ))}
      </div>
    </Shell>
  );
}
