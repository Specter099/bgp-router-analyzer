import type { ReactNode } from "react";

export function Pill({ status }: { status: string }) {
  return <span className={`pill ${status}`}>{status.replace(/_/g, " ")}</span>;
}

export function Banner({ kind, children }: { kind: "error" | "warn"; children: ReactNode }) {
  return (
    <div className={`banner ${kind}`} role={kind === "error" ? "alert" : "status"}>
      {children}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

/** Render an ISO timestamp in the viewer's locale, with the raw value on hover. */
export function Time({ value }: { value: string | null }) {
  if (!value) return <span className="muted">never</span>;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return <span className="mono">{value}</span>;
  return <time dateTime={value} title={value}>{date.toLocaleString()}</time>;
}

export function Delta({ value }: { value: number | null }) {
  if (value === null || value === 0) return <span className="muted">—</span>;
  return (
    <span className={`delta ${value > 0 ? "up" : "down"}`}>
      {value > 0 ? "+" : ""}
      {value}
    </span>
  );
}

export function Pager({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  if (total <= limit) return null;
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.ceil(total / limit);
  return (
    <div className="toolbar">
      <button disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
        ← Prev
      </button>
      <span className="muted">
        Page {page} of {pages} ({total} total)
      </span>
      <button disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>
        Next →
      </button>
    </div>
  );
}
