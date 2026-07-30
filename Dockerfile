# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1 — build the admin UI
#
# Node exists only here; the runtime image never sees it.
# ---------------------------------------------------------------------------
FROM node:22-alpine AS ui-build

WORKDIR /build

# Copy manifests first so the dependency layer caches independently of source.
COPY ui/package.json ui/package-lock.json ./
RUN npm ci

COPY ui/ ./
RUN npm run build && test -f dist/index.html


# ---------------------------------------------------------------------------
# Stage 2 — build the Python virtualenv
#
# Kept separate so compilers and headers pulled in by any source distribution
# stay out of the final image.
# ---------------------------------------------------------------------------
FROM python:3.13-slim AS py-build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Runtime dependencies only — pytest and httpx live in requirements-dev.txt.
COPY requirements.txt ./
RUN pip install -r requirements.txt


# ---------------------------------------------------------------------------
# Stage 3 — runtime
# ---------------------------------------------------------------------------
FROM python:3.13-slim AS runtime

LABEL org.opencontainers.image.title="BGP Route Analyzer" \
      org.opencontainers.image.description="BGP snapshot collection, diffing, and admin UI" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Specter099/bgp-router-analyzer"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BGP_DB_PATH=/data/bgp_snapshots.db \
    BGP_ROUTER_CONFIG=/config/routers.json

# Fixed UID/GID so a bind-mounted data volume has predictable ownership on
# the host. Running as root would also defeat init_db()'s 0600 chmod, since
# root can read the database regardless.
#
# A real home directory is required, not optional: ssh_strict defaults to True
# and paramiko's load_system_host_keys() reads ~/.ssh/known_hosts. Without
# somewhere to mount known_hosts, every poll would fail host-key verification
# and the only workaround would be ssh_strict: false — which this project
# treats as an invariant not to relax.
RUN groupadd --gid 10001 --system bgp \
 && useradd --uid 10001 --gid 10001 --system --create-home --home-dir /home/bgp \
            --shell /usr/sbin/nologin bgp \
 && mkdir -p /home/bgp/.ssh \
 && chown -R bgp:bgp /home/bgp \
 && chmod 700 /home/bgp/.ssh

WORKDIR /app

# Application files stay root-owned and read-only to the runtime user, so a
# compromised process cannot rewrite its own code.
COPY --from=py-build /opt/venv /opt/venv
COPY --chown=root:root bgp_route_analyzer.py docker-healthcheck.py ./
COPY --from=ui-build --chown=root:root /build/dist ./ui/dist

# /data holds the SQLite database. SQLite in WAL mode writes -wal and -shm
# siblings, so the *directory* must be writable by the runtime user, not just
# the database file. /config holds a read-only mount of routers.json.
RUN mkdir -p /data /config \
 && chown bgp:bgp /data \
 && chmod 700 /data

VOLUME ["/data"]
EXPOSE 8000

USER bgp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "/app/docker-healthcheck.py"]

# Exec form so the process is PID 1 and receives signals directly rather than
# through a shell that would swallow them.
#
# Note on shutdown: in --serve mode uvicorn installs its own signal handlers,
# and snapshot worker threads are daemons, so SIGTERM ends in-flight polls
# abruptly. That is safe — SQLite runs in WAL mode and each snapshot commits
# atomically — but it is not the graceful mid-poll drain that the CLI's
# _shutdown_event provides for --snapshot runs.
#
# 0.0.0.0 is correct inside a network namespace — publish the port
# deliberately, and set BGP_ANALYZER_API_KEY before exposing it.
ENTRYPOINT ["python", "bgp_route_analyzer.py"]
CMD ["--serve", "--host", "0.0.0.0", "--port", "8000"]
