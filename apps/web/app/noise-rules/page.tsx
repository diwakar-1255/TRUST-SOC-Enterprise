"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import Shell from "@/components/Shell";
import { NoisePolicy, formatDate, request } from "@/lib/api";

export default function NoiseRulesPage() {
  const [policies, setPolicies] = useState<NoisePolicy[]>([]);
  const [name, setName] = useState("Suppress Wazuh summary events");
  const [ruleIds, setRuleIds] = useState("60608");
  const [reason, setReason] = useState("Known repetitive Windows signature summary event.");
  const [error, setError] = useState("");
  const router = useRouter();

  async function load() {
    try { setPolicies(await request<NoisePolicy[]>("/operations/noise-policies")); setError(""); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "Unable to load noise policies"); }
  }
  useEffect(() => {
    if (!localStorage.getItem("access_token")) { router.push("/login"); return; }
    void load();
  }, [router]);

  async function create(event: FormEvent) {
    event.preventDefault();
    try {
      await request("/operations/noise-policies", {
        method: "POST",
        body: JSON.stringify({
          name,
          action: "suppress",
          match_rule_ids: ruleIds.split(",").map((item) => item.trim()).filter(Boolean),
          match_agent_pattern: null,
          match_title_pattern: null,
          match_severities: [],
          match_groups: [],
          target_severity: null,
          reason,
          enabled: true,
          description: "Analyst-managed alert noise policy.",
          expires_at: null,
        }),
      });
      await load();
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Policy creation failed"); }
  }

  async function toggle(policy: NoisePolicy) {
    await request(`/operations/noise-policies/${policy.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !policy.enabled }) });
    await load();
  }
  async function remove(id: string) {
    await request(`/operations/noise-policies/${id}`, { method: "DELETE" });
    await load();
  }

  return <Shell>
    <div className="header"><div><div className="eyebrow">Detection engineering</div><h1>Alert noise policies</h1><p className="subtitle">Suppress or downgrade known benign patterns without deleting raw evidence.</p></div></div>
    {error && <div className="card error">{error}</div>}
    <div className="content-grid">
      <form className="card section policy-form" onSubmit={create}>
        <h2>Create suppression policy</h2>
        <label className="field">Name<input value={name} onChange={(event) => setName(event.target.value)} required /></label>
        <label className="field">Wazuh rule IDs<input value={ruleIds} onChange={(event) => setRuleIds(event.target.value)} placeholder="60608,60642" /></label>
        <label className="field">Reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} /></label>
        <button className="primary" type="submit">Create policy</button>
      </form>
      <section className="card section"><h2>How it works</h2><p className="muted">Policies apply during synchronization. Matching raw alerts remain stored and auditable, while their correlated groups are marked suppressed or downgraded.</p><p className="muted">Use narrow rule, endpoint, title, severity, or group conditions. Review policies regularly and set expiration dates for temporary exceptions.</p></section>
    </div>
    <section className="card section"><div className="table-wrap"><table>
      <thead><tr><th>Policy</th><th>Action</th><th>Match</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
      <tbody>{policies.length ? policies.map((policy) => <tr key={policy.id}>
        <td><strong>{policy.name}</strong><div className="table-subtitle">{policy.reason || policy.description}</div></td>
        <td>{policy.action}{policy.target_severity ? ` → ${policy.target_severity}` : ""}</td>
        <td>Rules: {policy.match_rule_ids.join(", ") || "Any"}<div className="table-subtitle">Agent: {policy.match_agent_pattern || "Any"}</div></td>
        <td><span className={`badge ${policy.enabled ? "healthy" : "unknown"}`}>{policy.enabled ? "enabled" : "disabled"}</span></td>
        <td>{formatDate(policy.created_at)}</td>
        <td><div className="action-stack"><button className="mini-button" onClick={() => toggle(policy)}>{policy.enabled ? "Disable" : "Enable"}</button><button className="mini-button danger" onClick={() => remove(policy.id)}>Delete</button></div></td>
      </tr>) : <tr><td colSpan={6} className="empty-state">No noise policies configured.</td></tr>}</tbody>
    </table></div></section>
  </Shell>;
}
