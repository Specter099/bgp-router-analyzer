import { useCallback, useEffect, useRef, useState } from "react";
import { api, type Job, type RouterHealth } from "../api";
import { Banner, Delta, Empty, Pill, Time } from "./common";

const POLL_INTERVAL_MS = 1500;

export function Routers({ onOpenSnapshot }: { onOpenSnapshot: (id: number) => void }) {
  const [routers, setRouters] = useState<RouterHealth[] | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const timer = useRef<number | null>(null);

  const load = useCallback(async () => {
    try {
      setRouters(await api.routers());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load routers");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Poll the running job until it settles, then refresh the inventory once so
  // last-poll times and prefix counts reflect what just happened.
  useEffect(() => {
    if (!job || job.status !== "running") return;
    timer.current = window.setInterval(async () => {
      try {
        const next = await api.job(job.id);
        setJob(next);
        if (next.status !== "running") void load();
      } catch {
        /* transient; the next tick retries */
      }
    }, POLL_INTERVAL_MS);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [job, load]);

  // Reattach to a job still running from a previous page load.
  useEffect(() => {
    void (async () => {
      try {
        const recent = await api.jobs(1);
        if (recent[0]?.status === "running") setJob(recent[0]);
      } catch {
        /* nothing running, or not permitted — nothing to attach to */
      }
    })();
  }, []);

  async function trigger() {
    setStarting(true);
    setError(null);
    try {
      setJob(await api.startSnapshot());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start snapshot");
    } finally {
      setStarting(false);
    }
  }

  const running = job?.status === "running";
  const percent = job && job.total ? Math.round((job.completed / job.total) * 100) : 0;

  return (
    <>
      {error && <Banner kind="error">{error}</Banner>}

      <div className="panel">
        <div className="panel-head">
          <h2>Routers</h2>
          <button className="primary" onClick={trigger} disabled={starting || running}>
            {running ? "Snapshot running…" : starting ? "Starting…" : "Take snapshot"}
          </button>
        </div>

        {job && (
          <div className="card">
            <h3>
              <span>
                Snapshot job <span className="mono">{job.id.slice(0, 8)}</span>
              </span>
              <Pill status={job.status} />
            </h3>
            {/* Native <progress> keeps this CSP-clean: an inline style attribute
                would be blocked by `style-src 'self'`. */}
            <progress className="progress" value={job.completed} max={job.total || 1}>
              {percent}%
            </progress>
            <p className="muted">
              {job.completed} of {job.total} routers · {job.succeeded} succeeded · {job.failed} failed
            </p>
            {job.error && <Banner kind="error">{job.error}</Banner>}
            {job.routers.length > 0 && (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Router</th>
                      <th>Result</th>
                      <th className="num">Prefixes</th>
                      <th className="num">Duration</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {job.routers.map((r) => (
                      <tr key={r.router}>
                        <td>{r.router}</td>
                        <td>
                          <Pill status={r.status} />
                        </td>
                        <td className="num">{r.prefix_count}</td>
                        <td className="num">{r.duration_seconds !== null ? `${r.duration_seconds}s` : "—"}</td>
                        <td className="muted">
                          {r.error ?? (r.snapshot_id ? `snapshot #${r.snapshot_id}` : "—")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="panel">
        {routers === null ? (
          <Empty>Loading…</Empty>
        ) : routers.length === 0 ? (
          <Empty>No routers configured. Create routers.json or pass --router-config.</Empty>
        ) : (
          <div className="grid">
            {routers.map((r) => (
              <div className="card" key={r.name}>
                <h3>
                  <span>{r.name}</span>
                  <Pill status={r.status} />
                </h3>
                <dl>
                  <dt>Type</dt>
                  <dd className="mono">{r.device_type ?? "—"}</dd>
                  <dt>Host</dt>
                  <dd className="mono">{r.host_masked || "—"}</dd>
                  <dt>Last poll</dt>
                  <dd>
                    <Time value={r.last_captured_at} />
                  </dd>
                  <dt>Prefixes</dt>
                  <dd>
                    {r.prefix_count ?? "—"} <Delta value={r.prefix_delta} />
                  </dd>
                </dl>
                {r.last_error && (
                  <p className="muted">
                    Last error (<Time value={r.last_error_at} />): {r.last_error}
                  </p>
                )}
                {r.last_snapshot_id !== null && (
                  <p>
                    <button onClick={() => onOpenSnapshot(r.last_snapshot_id!)}>
                      View latest snapshot
                    </button>
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
