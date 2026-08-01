const API = process.env.NEXT_PUBLIC_API_BASE_URL || "/api";

export type Source = {
  id: string;
  name: string;
  source_type: string;
  status: string;
  trust_score: number;
  last_heartbeat_at: string | null;
};

export type Blindness = {
  source_id: string;
  source_name: string;
  source_status: string;
  coverage_loss_percent: number;
  severity: string;
  affected_techniques: string[];
  affected_rules: { name: string }[];
};

export type SecurityAlert = {
  id: string;
  external_id: string;
  integration: string;
  event_timestamp: string;
  agent_id: string | null;
  agent_name: string | null;
  agent_ip: string | null;
  rule_id: string;
  rule_level: number;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | string;
  groups: string[];
  mitre_techniques: string[];
  mitre_tactics: string[];
  status: string;
};

export type IntegrationStatus = {
  enabled: boolean;
  status: string;
  manager_connected: boolean;
  indexer_connected: boolean;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  synchronized_agents: number;
  synchronized_alerts: number;
};

export type PortalSummary = {
  telemetry_trust_score: number;
  protected_assets: number;
  telemetry_sources: number;
  critical_sources: number;
  enabled_detections: number;
  events_24h: number;
  wazuh_agents_total: number;
  wazuh_agents_active: number;
  wazuh_agents_disconnected: number;
  alerts_24h: number;
  grouped_alerts_24h: number;
  suppressed_alerts_24h: number;
  open_incidents: number;
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  mitre_techniques: { technique: string; count: number }[];
  recent_alerts: SecurityAlert[];
  integration: IntegrationStatus;
};

export type PortalAsset = {
  id: string;
  hostname: string;
  asset_type: string;
  operating_system: string;
  criticality: number;
  active: boolean;
  wazuh_agent_id: string | null;
  wazuh_status: string | null;
  telemetry_sources: number;
  source_health: string;
  last_seen: string | null;
};

export type AlertGroup = {
  id: string;
  fingerprint: string;
  integration: string;
  window_start: string;
  window_end: string;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
  agent_id: string | null;
  agent_name: string | null;
  agent_ip: string | null;
  rule_id: string;
  max_rule_level: number;
  title: string;
  severity: string;
  risk_score: number;
  groups: string[];
  mitre_techniques: string[];
  mitre_tactics: string[];
  status: string;
  assigned_to: string | null;
  incident_id: string | null;
  suppression_policy_id: string | null;
  suppression_reason: string | null;
  acknowledged_at: string | null;
  created_at: string;
  updated_at: string;
};

export type AlertGroupDetail = AlertGroup & {
  raw_alerts: SecurityAlert[];
};

export type SecurityIncident = {
  id: string;
  case_number: string;
  title: string;
  description: string;
  severity: string;
  priority: string;
  status: string;
  risk_score: number;
  source: string;
  assigned_to: string | null;
  created_by: string | null;
  first_seen: string;
  last_seen: string;
  alert_group_count: number;
  occurrence_count: number;
  affected_assets: string[];
  mitre_techniques: string[];
  mitre_tactics: string[];
  tags: Record<string, unknown>;
  sla_due_at: string | null;
  acknowledged_at: string | null;
  contained_at: string | null;
  resolved_at: string | null;
  resolution_summary: string | null;
  created_at: string;
  updated_at: string;
};

export type IncidentDetail = SecurityIncident & {
  alert_groups: AlertGroup[];
};

export type NoisePolicy = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  action: "suppress" | "downgrade";
  match_rule_ids: string[];
  match_agent_pattern: string | null;
  match_title_pattern: string | null;
  match_severities: string[];
  match_groups: string[];
  target_severity: string | null;
  reason: string;
  expires_at: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
};

export type OperationsSummary = {
  open_incidents: number;
  acknowledged_incidents: number;
  investigating_incidents: number;
  critical_incidents: number;
  grouped_alerts_24h: number;
  suppressed_alerts_24h: number;
  unacknowledged_groups: number;
};

type TokenResponse = {
  access_token: string;
  refresh_token: string;
  token_type?: string;
};

let refreshInProgress: Promise<string | null> | null = null;

function accessToken(): string | null {
  return typeof window === "undefined"
    ? null
    : localStorage.getItem("access_token");
}

function refreshToken(): string | null {
  return typeof window === "undefined"
    ? null
    : localStorage.getItem("refresh_token");
}

function clearSession(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
}

function redirectToLogin(): void {
  if (typeof window === "undefined") return;
  if (window.location.pathname !== "/login") {
    window.location.replace("/login");
  }
}

async function errorMessage(response: Response): Promise<string> {
  const payload = await response
    .json()
    .catch(() => ({ detail: response.statusText || "Request failed" }));
  return typeof payload?.detail === "string"
    ? payload.detail
    : "Request failed";
}

async function renewAccessToken(): Promise<string | null> {
  const storedRefreshToken = refreshToken();
  if (!storedRefreshToken) {
    clearSession();
    return null;
  }
  if (refreshInProgress) return refreshInProgress;

  refreshInProgress = (async () => {
    const response = await fetch(`${API}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: storedRefreshToken }),
      cache: "no-store",
    });
    if (!response.ok) {
      clearSession();
      return null;
    }
    const data = (await response.json()) as TokenResponse;
    localStorage.setItem("access_token", data.access_token);
    localStorage.setItem("refresh_token", data.refresh_token);
    return data.access_token;
  })()
    .catch(() => {
      clearSession();
      return null;
    })
    .finally(() => {
      refreshInProgress = null;
    });

  return refreshInProgress;
}

async function fetchWithToken(
  path: string,
  init: RequestInit,
  token: string | null,
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return fetch(`${API}${path}`, { ...init, headers, cache: "no-store" });
}

export async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const isAuthRequest = path === "/auth/login" || path === "/auth/refresh";
  const currentToken = isAuthRequest ? null : accessToken();
  let response = await fetchWithToken(path, init, currentToken);

  if (response.status === 401 && !isAuthRequest && currentToken) {
    const renewedToken = await renewAccessToken();
    if (renewedToken) {
      response = await fetchWithToken(path, init, renewedToken);
    } else {
      redirectToLogin();
      throw new Error("Session expired. Please sign in again.");
    }
  }

  if (!response.ok) {
    if (response.status === 401 && !isAuthRequest) {
      clearSession();
      redirectToLogin();
    }
    throw new Error(await errorMessage(response));
  }

  return response.json() as Promise<T>;
}

export function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "Never";
}


export type HoneypotEvent = {
  id: string;
  external_event_id: string;
  observed_at: string;
  source_ip: string;
  service: string;
  event_type: string;
  attack_type: string;
  username: string | null;
  path: string | null;
  user_agent: string | null;
  risk_score: number;
  severity: string;
  geo: Record<string, unknown>;
};

export type HoneypotAttacker = {
  id: string;
  source_ip: string;
  country: string | null;
  city: string | null;
  isp: string | null;
  asn: string | null;
  first_seen: string | null;
  last_seen: string | null;
  total_events: number;
  risk_score: number;
  severity: string;
};

export type HoneypotIntegrationStatus = {
  enabled: boolean;
  status: string;
  api_connected: boolean;
  grafana_url: string;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  synchronized_events: number;
  synchronized_alerts: number;
  synchronized_attackers: number;
  total_events: number;
  total_alerts: number;
  total_attackers: number;
};

export type HoneypotSummary = {
  integration: HoneypotIntegrationStatus;
  by_service: Record<string, number>;
  alerts_by_severity: Record<string, number>;
  recent_events: HoneypotEvent[];
  top_attackers: HoneypotAttacker[];
  critical_alerts: SecurityAlert[];
};
