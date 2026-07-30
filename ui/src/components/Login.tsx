import { useState } from "react";
import { api, ApiError } from "../api";
import { Banner } from "./common";

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(apiKey);
      // Drop the key from component state as soon as it has been exchanged
      // for a session cookie — nothing should keep it around.
      setApiKey("");
      onSuccess();
    } catch (err) {
      const message =
        err instanceof ApiError && err.status === 429
          ? "Too many login attempts. Wait a minute and try again."
          : err instanceof Error
            ? err.message
            : "Login failed";
      setError(message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <div className="login">
        <h1>BGP Route Analyzer</h1>
        <p className="muted">Sign in with the analyzer API key to continue.</p>
        {error && <Banner kind="error">{error}</Banner>}
        <form onSubmit={submit}>
          <label htmlFor="api-key">API key</label>
          <input
            id="api-key"
            type="password"
            autoComplete="current-password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            required
            autoFocus
          />
          <button className="primary" type="submit" disabled={busy || !apiKey}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
