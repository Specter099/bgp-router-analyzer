/**
 * API client.
 *
 * Authentication is cookie-based: the session cookie is HttpOnly, so this
 * file never sees or stores the credential. The only thing it handles is the
 * CSRF token, which the server also sets as a readable cookie and expects
 * echoed back in a header on mutating requests.
 */

export type AuthStatus = {
  auth_required: boolean;
  authenticated: boolean;
  actor: string | null;
  csrf_token: string | null;
};

export type SnapshotListItem = {
  id: number;
  router: string;
  captured_at: string;
  prefix_count: number | null;
};

export type Page<T> = { items: T[]; total: number; limit: number; offset: number };

export type Prefix = {
  network: string;
  next_hop: string | null;
  metric: string | null;
  local_pref: string | null;
  weight: string | null;
  as_path: string | null;
  origin: string | null;
};

export type SnapshotDetail = {
  snapshot: SnapshotListItem;
  prefix_count: number;
  prefixes: Prefix[];
  prefix_limit: number;
  prefix_offset: number;
};

export type AttributeChange = { before: string | null; after: string | null };

export type PrefixChange = {
  network: string;
  next_hop: string | null;
  changes: Record<string, AttributeChange>;
};

export type Diff = {
  before_snapshot_id: number;
  after_snapshot_id: number;
  summary: { added: number; removed: number; changed: number };
  added: Prefix[];
  removed: Prefix[];
  changed: PrefixChange[];
  before_router: string | null;
  after_router: string | null;
  cross_router: boolean;
};

export type JobRouterResult = {
  router: string;
  status: string;
  snapshot_id: number | null;
  prefix_count: number;
  error: string | null;
  duration_seconds: number | null;
};

export type Job = {
  id: string;
  status: "running" | "completed" | "failed";
  started_at: string;
  finished_at: string | null;
  actor: string;
  total: number;
  completed: number;
  succeeded: number;
  failed: number;
  snapshot_ids: number[];
  routers: JobRouterResult[];
  error: string | null;
};

export type RouterHealth = {
  name: string;
  device_type: string | null;
  host_masked: string;
  last_snapshot_id: number | null;
  last_captured_at: string | null;
  prefix_count: number | null;
  previous_prefix_count: number | null;
  prefix_delta: number | null;
  status: "ok" | "error" | "never_polled";
  last_error: string | null;
  last_error_at: string | null;
};

export type AuditEntry = {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  outcome: string;
  target: string | null;
  source_ip: string | null;
  detail: string | null;
};

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Read the non-HttpOnly CSRF cookie the server sets alongside the session. */
function csrfToken(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)bgp_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : null;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);

  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const token = csrfToken();
    if (token) headers.set("X-CSRF-Token", token);
    if (init.body) headers.set("Content-Type", "application/json");
  }

  const resp = await fetch(path, {
    ...init,
    headers,
    // Send cookies, and never let a stale response stand in for live data.
    credentials: "same-origin",
    cache: "no-store",
  });

  if (!resp.ok) {
    let detail = `${resp.status} ${resp.statusText}`;
    try {
      const body = await resp.json();
      if (body?.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body; keep the status line */
    }
    throw new ApiError(resp.status, detail);
  }

  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

const qs = (params: Record<string, string | number | undefined | null>): string => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const s = search.toString();
  return s ? `?${s}` : "";
};

export const api = {
  authStatus: () => request<AuthStatus>("/auth/status"),

  login: (apiKey: string) =>
    request<{ actor: string; csrf_token: string; expires_in: number }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ api_key: apiKey }),
      headers: { "Content-Type": "application/json" },
    }),

  logout: () => request<{ status: string }>("/auth/logout", { method: "POST" }),

  routers: () => request<RouterHealth[]>("/routers"),

  snapshots: (opts: { router?: string; limit?: number; offset?: number; since?: string; until?: string } = {}) =>
    request<Page<SnapshotListItem>>(`/snapshots${qs(opts)}`),

  snapshot: (id: number, opts: { prefix_limit?: number; prefix_offset?: number } = {}) =>
    request<SnapshotDetail>(`/snapshots/${id}${qs(opts)}`),

  diff: (before: number, after: number) => request<Diff>(`/diff${qs({ before, after })}`),

  startSnapshot: () => request<Job>("/snapshots", { method: "POST" }),

  job: (id: string) => request<Job>(`/jobs/${id}`),

  jobs: (limit = 20) => request<Job[]>(`/jobs${qs({ limit })}`),

  audit: (opts: { action?: string; limit?: number; offset?: number } = {}) =>
    request<Page<AuditEntry>>(`/audit${qs(opts)}`),
};
