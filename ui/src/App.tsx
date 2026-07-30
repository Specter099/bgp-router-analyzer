import { useCallback, useEffect, useState } from "react";
import { api, ApiError, type AuthStatus } from "./api";
import { AuditLog, DiffView } from "./components/DiffView";
import { Banner } from "./components/common";
import { Login } from "./components/Login";
import { Routers } from "./components/Routers";
import { Snapshots } from "./components/Snapshots";

type Tab = "routers" | "snapshots" | "diff" | "audit";

const TABS: { id: Tab; label: string }[] = [
  { id: "routers", label: "Routers" },
  { id: "snapshots", label: "Snapshots" },
  { id: "diff", label: "Compare" },
  { id: "audit", label: "Audit" },
];

export function App() {
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [tab, setTab] = useState<Tab>("routers");
  const [selectedSnapshot, setSelectedSnapshot] = useState<number | null>(null);
  const [diffPair, setDiffPair] = useState<{ before: number; after: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refreshAuth = useCallback(async () => {
    try {
      setAuth(await api.authStatus());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cannot reach the analyzer API");
    }
  }, []);

  useEffect(() => {
    void refreshAuth();
  }, [refreshAuth]);

  // A session can expire mid-session; any 403 sends the operator back to login
  // rather than leaving a dashboard full of stale errors.
  useEffect(() => {
    const onRejection = (event: PromiseRejectionEvent) => {
      if (event.reason instanceof ApiError && event.reason.status === 403) {
        void refreshAuth();
      }
    };
    window.addEventListener("unhandledrejection", onRejection);
    return () => window.removeEventListener("unhandledrejection", onRejection);
  }, [refreshAuth]);

  async function logout() {
    try {
      await api.logout();
    } finally {
      await refreshAuth();
    }
  }

  if (error && auth === null) {
    return (
      <main>
        <Banner kind="error">{error}</Banner>
      </main>
    );
  }

  if (auth === null) return <main className="empty">Loading…</main>;

  if (auth.auth_required && !auth.authenticated) {
    return <Login onSuccess={refreshAuth} />;
  }

  return (
    <div className="app">
      <header className="topbar">
        <h1>BGP Route Analyzer</h1>
        <nav className="tabs">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={tab === t.id ? "active" : ""}
              aria-current={tab === t.id ? "page" : undefined}
              onClick={() => {
                setTab(t.id);
                if (t.id !== "snapshots") setSelectedSnapshot(null);
              }}
            >
              {t.label}
            </button>
          ))}
        </nav>
        {auth.auth_required ? (
          <>
            <span className="muted">{auth.actor}</span>
            <button onClick={logout}>Sign out</button>
          </>
        ) : (
          <span className="muted" title="BGP_ANALYZER_API_KEY is not set">
            authentication disabled
          </span>
        )}
      </header>

      <main>
        {!auth.auth_required && (
          <Banner kind="warn">
            API authentication is disabled because BGP_ANALYZER_API_KEY is not set. Anyone who
            can reach this server has full access.
          </Banner>
        )}

        {tab === "routers" && (
          <Routers
            onOpenSnapshot={(id) => {
              setSelectedSnapshot(id);
              setTab("snapshots");
            }}
          />
        )}

        {tab === "snapshots" && (
          <Snapshots
            selectedId={selectedSnapshot}
            onSelect={setSelectedSnapshot}
            onCompare={(before, after) => {
              setDiffPair({ before, after });
              setTab("diff");
            }}
          />
        )}

        {tab === "diff" && (
          <DiffView before={diffPair?.before ?? null} after={diffPair?.after ?? null} />
        )}

        {tab === "audit" && <AuditLog />}
      </main>
    </div>
  );
}
