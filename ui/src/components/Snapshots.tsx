import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type Page, type SnapshotDetail, type SnapshotListItem } from "../api";
import { Banner, Empty, Pager, Time } from "./common";

const PAGE_SIZE = 25;
const PREFIX_PAGE_SIZE = 500;

export function Snapshots({
  selectedId,
  onSelect,
  onCompare,
}: {
  selectedId: number | null;
  onSelect: (id: number | null) => void;
  onCompare: (before: number, after: number) => void;
}) {
  const [page, setPage] = useState<Page<SnapshotListItem> | null>(null);
  const [offset, setOffset] = useState(0);
  const [routerFilter, setRouterFilter] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [checked, setChecked] = useState<number[]>([]);

  const load = useCallback(async () => {
    setError(null);
    try {
      setPage(
        await api.snapshots({
          limit: PAGE_SIZE,
          offset,
          router: routerFilter || undefined,
          // <input type="datetime-local"> yields no timezone; treat as UTC.
          since: since ? `${since}:00+00:00` : undefined,
          until: until ? `${until}:00+00:00` : undefined,
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load snapshots");
    }
  }, [offset, routerFilter, since, until]);

  useEffect(() => {
    void load();
  }, [load]);

  function toggle(id: number) {
    setChecked((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id].slice(-2),
    );
  }

  if (selectedId !== null) {
    return <SnapshotDetailView id={selectedId} onBack={() => onSelect(null)} />;
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Snapshots</h2>
        <button
          className="primary"
          disabled={checked.length !== 2}
          onClick={() => {
            const [a, b] = [...checked].sort((x, y) => x - y);
            onCompare(a, b);
          }}
        >
          Compare selected ({checked.length}/2)
        </button>
      </div>

      {error && <Banner kind="error">{error}</Banner>}

      <div className="toolbar">
        <label htmlFor="f-router">Router</label>
        <input
          id="f-router"
          value={routerFilter}
          placeholder="all routers"
          onChange={(e) => {
            setRouterFilter(e.target.value);
            setOffset(0);
          }}
        />
        <label htmlFor="f-since">From</label>
        <input
          id="f-since"
          type="datetime-local"
          value={since}
          onChange={(e) => {
            setSince(e.target.value);
            setOffset(0);
          }}
        />
        <label htmlFor="f-until">To</label>
        <input
          id="f-until"
          type="datetime-local"
          value={until}
          onChange={(e) => {
            setUntil(e.target.value);
            setOffset(0);
          }}
        />
        <button
          onClick={() => {
            setRouterFilter("");
            setSince("");
            setUntil("");
            setOffset(0);
          }}
        >
          Clear
        </button>
        <span className="spacer" />
        <button onClick={() => void load()}>Refresh</button>
      </div>

      {page === null ? (
        <Empty>Loading…</Empty>
      ) : page.items.length === 0 ? (
        <Empty>No snapshots match these filters.</Empty>
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Compare</th>
                  <th>ID</th>
                  <th>Router</th>
                  <th>Captured</th>
                  <th className="num">Prefixes</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {page.items.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Select snapshot ${s.id} for comparison`}
                        checked={checked.includes(s.id)}
                        onChange={() => toggle(s.id)}
                      />
                    </td>
                    <td className="mono">#{s.id}</td>
                    <td>{s.router}</td>
                    <td>
                      <Time value={s.captured_at} />
                    </td>
                    <td className="num">{s.prefix_count ?? "—"}</td>
                    <td>
                      <button onClick={() => onSelect(s.id)}>View</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager total={page.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
        </>
      )}
    </div>
  );
}

function SnapshotDetailView({ id, onBack }: { id: number; onBack: () => void }) {
  const [detail, setDetail] = useState<SnapshotDetail | null>(null);
  const [prefixOffset, setPrefixOffset] = useState(0);
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setError(null);
    api
      .snapshot(id, { prefix_limit: PREFIX_PAGE_SIZE, prefix_offset: prefixOffset })
      .then(setDetail)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load snapshot"));
  }, [id, prefixOffset]);

  // Filtering is client-side over the loaded page; the server-side pager below
  // moves between pages of a large table.
  const visible = useMemo(() => {
    if (!detail) return [];
    const q = search.trim().toLowerCase();
    if (!q) return detail.prefixes;
    return detail.prefixes.filter((p) =>
      [p.network, p.next_hop, p.as_path, p.origin]
        .filter(Boolean)
        .some((field) => field!.toLowerCase().includes(q)),
    );
  }, [detail, search]);

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Snapshot #{id}</h2>
        <button onClick={onBack}>← Back to list</button>
      </div>

      {error && <Banner kind="error">{error}</Banner>}

      {detail === null ? (
        <Empty>Loading…</Empty>
      ) : (
        <>
          <div className="stat-row">
            <div className="stat">
              <div className="value">{detail.snapshot.router}</div>
              <div className="label">Router</div>
            </div>
            <div className="stat">
              <div className="value">{detail.prefix_count}</div>
              <div className="label">Prefixes</div>
            </div>
            <div className="stat">
              <div className="value">
                <Time value={detail.snapshot.captured_at} />
              </div>
              <div className="label">Captured</div>
            </div>
          </div>

          <div className="toolbar">
            <label htmlFor="p-search">Filter</label>
            <input
              id="p-search"
              value={search}
              placeholder="network, next hop, AS path…"
              onChange={(e) => setSearch(e.target.value)}
            />
            <span className="muted">
              {visible.length} of {detail.prefixes.length} shown on this page
            </span>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Network</th>
                  <th>Next hop</th>
                  <th className="num">Metric</th>
                  <th className="num">Local pref</th>
                  <th className="num">Weight</th>
                  <th>AS path</th>
                  <th>Origin</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((p, i) => (
                  <tr key={`${p.network}-${p.next_hop}-${i}`}>
                    <td className="mono">{p.network}</td>
                    <td className="mono">{p.next_hop}</td>
                    <td className="num">{p.metric || "—"}</td>
                    <td className="num">{p.local_pref || "—"}</td>
                    <td className="num">{p.weight || "—"}</td>
                    <td className="mono">{p.as_path || "—"}</td>
                    <td>{p.origin || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <Pager
            total={detail.prefix_count}
            limit={PREFIX_PAGE_SIZE}
            offset={prefixOffset}
            onChange={setPrefixOffset}
          />
        </>
      )}
    </div>
  );
}
