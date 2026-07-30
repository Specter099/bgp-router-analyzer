import { useEffect, useState } from "react";
import { api, type Diff } from "../api";
import { Banner, Empty, Time } from "./common";

export function DiffView({
  before: initialBefore,
  after: initialAfter,
}: {
  before: number | null;
  after: number | null;
}) {
  const [before, setBefore] = useState(initialBefore?.toString() ?? "");
  const [after, setAfter] = useState(initialAfter?.toString() ?? "");
  const [diff, setDiff] = useState<Diff | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(b: number, a: number) {
    setBusy(true);
    setError(null);
    try {
      setDiff(await api.diff(b, a));
    } catch (err) {
      setDiff(null);
      setError(err instanceof Error ? err.message : "Diff failed");
    } finally {
      setBusy(false);
    }
  }

  // Auto-run when the Snapshots tab handed us a pair to compare.
  useEffect(() => {
    if (initialBefore !== null && initialAfter !== null) {
      void run(initialBefore, initialAfter);
    }
  }, [initialBefore, initialAfter]);

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const b = Number(before);
    const a = Number(after);
    if (!Number.isInteger(b) || !Number.isInteger(a) || b < 1 || a < 1) {
      setError("Enter two positive snapshot IDs.");
      return;
    }
    if (b === a) {
      setError("Choose two different snapshots.");
      return;
    }
    void run(b, a);
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Compare snapshots</h2>
      </div>

      <form className="toolbar" onSubmit={submit}>
        <label htmlFor="d-before">Before</label>
        <input
          id="d-before"
          type="number"
          min="1"
          value={before}
          onChange={(e) => setBefore(e.target.value)}
          required
        />
        <label htmlFor="d-after">After</label>
        <input
          id="d-after"
          type="number"
          min="1"
          value={after}
          onChange={(e) => setAfter(e.target.value)}
          required
        />
        <button className="primary" type="submit" disabled={busy}>
          {busy ? "Comparing…" : "Compare"}
        </button>
      </form>

      {error && <Banner kind="error">{error}</Banner>}

      {diff && (
        <>
          {diff.cross_router && (
            <Banner kind="warn">
              These snapshots are from different routers ({diff.before_router} →{" "}
              {diff.after_router}). A large number of added and removed prefixes is expected
              here and does not indicate a routing incident.
            </Banner>
          )}

          <div className="stat-row">
            <div className="stat added">
              <div className="value">+{diff.summary.added}</div>
              <div className="label">Added</div>
            </div>
            <div className="stat removed">
              <div className="value">−{diff.summary.removed}</div>
              <div className="label">Removed</div>
            </div>
            <div className="stat changed">
              <div className="value">{diff.summary.changed}</div>
              <div className="label">Changed</div>
            </div>
          </div>

          {diff.summary.added + diff.summary.removed + diff.summary.changed === 0 ? (
            <Empty>No differences between these snapshots.</Empty>
          ) : (
            <>
              <PrefixSection
                title="Added prefixes"
                rowClass="added"
                rows={diff.added}
                emptyLabel="No prefixes added."
              />
              <PrefixSection
                title="Removed prefixes"
                rowClass="removed"
                rows={diff.removed}
                emptyLabel="No prefixes removed."
              />
              <ChangedSection changes={diff.changed} />
            </>
          )}
        </>
      )}
    </div>
  );
}

function PrefixSection({
  title,
  rowClass,
  rows,
  emptyLabel,
}: {
  title: string;
  rowClass: string;
  rows: Diff["added"];
  emptyLabel: string;
}) {
  return (
    <section>
      <h3>
        {title} ({rows.length})
      </h3>
      {rows.length === 0 ? (
        <Empty>{emptyLabel}</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Network</th>
                <th>Next hop</th>
                <th className="num">Metric</th>
                <th className="num">Local pref</th>
                <th>AS path</th>
                <th>Origin</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((p, i) => (
                <tr className={rowClass} key={`${p.network}-${p.next_hop}-${i}`}>
                  <td className="mono">{p.network}</td>
                  <td className="mono">{p.next_hop}</td>
                  <td className="num">{p.metric || "—"}</td>
                  <td className="num">{p.local_pref || "—"}</td>
                  <td className="mono">{p.as_path || "—"}</td>
                  <td>{p.origin || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ChangedSection({ changes }: { changes: Diff["changed"] }) {
  return (
    <section>
      <h3>Changed prefixes ({changes.length})</h3>
      {changes.length === 0 ? (
        <Empty>No attribute changes.</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Network</th>
                <th>Next hop</th>
                <th>Attribute</th>
                <th>Before</th>
                <th>After</th>
              </tr>
            </thead>
            <tbody>
              {changes.flatMap((c) =>
                Object.entries(c.changes).map(([attr, delta], i) => (
                  <tr className="changed" key={`${c.network}-${c.next_hop}-${attr}`}>
                    {i === 0 ? (
                      <>
                        <td className="mono" rowSpan={Object.keys(c.changes).length}>
                          {c.network}
                        </td>
                        <td className="mono" rowSpan={Object.keys(c.changes).length}>
                          {c.next_hop}
                        </td>
                      </>
                    ) : null}
                    <td>{attr.replace(/_/g, " ")}</td>
                    <td className="mono">{delta.before || "—"}</td>
                    <td className="mono">{delta.after || "—"}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function AuditLog() {
  const [entries, setEntries] = useState<
    { items: import("../api").AuditEntry[]; total: number } | null
  >(null);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const limit = 50;

  useEffect(() => {
    api
      .audit({ limit, offset })
      .then(setEntries)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load audit log"));
  }, [offset]);

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Audit log</h2>
      </div>
      {error && <Banner kind="error">{error}</Banner>}
      {entries === null ? (
        <Empty>Loading…</Empty>
      ) : entries.items.length === 0 ? (
        <Empty>No audit entries yet.</Empty>
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Outcome</th>
                  <th>Target</th>
                  <th>Source IP</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {entries.items.map((e) => (
                  <tr key={e.id}>
                    <td>
                      <Time value={e.timestamp} />
                    </td>
                    <td>{e.actor}</td>
                    <td className="mono">{e.action}</td>
                    <td>
                      <span className={`pill ${e.outcome === "success" ? "ok" : "error"}`}>
                        {e.outcome}
                      </span>
                    </td>
                    <td className="mono">{e.target ?? "—"}</td>
                    <td className="mono">{e.source_ip ?? "—"}</td>
                    <td className="muted">{e.detail ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="toolbar">
            <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
              ← Prev
            </button>
            <span className="muted">{entries.total} entries</span>
            <button disabled={offset + limit >= entries.total} onClick={() => setOffset(offset + limit)}>
              Next →
            </button>
          </div>
        </>
      )}
    </div>
  );
}
