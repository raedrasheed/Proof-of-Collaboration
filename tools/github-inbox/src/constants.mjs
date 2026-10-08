// Pinned scope of the GitHub inbox adapter. These values are not configurable at run time: a config
// file must repeat them exactly (see config.mjs), so a typo or an edited file cannot widen the scope.

export const PINNED = Object.freeze({
  owner: 'raedrasheed',
  repo: 'Proof-of-Collaboration',
  issue: 8,
  ownerLogin: 'raedrasheed',
  ownerId: 36733882,
});

export const REPO_FULL = `${PINNED.owner}/${PINNED.repo}`;
/** Forced on every gh call (`--hostname`); GH_HOST is removed from the child environment. */
export const GH_HOSTNAME = 'github.com';
export const ISSUE_API_URL = `https://api.github.com/repos/${REPO_FULL}/issues/${PINNED.issue}`;
export const ISSUE_HTML_URL = `https://github.com/${REPO_FULL}/issues/${PINNED.issue}`;
/** The ONLY GitHub REST path the adapter uses (with a numeric page for listing). */
export const COMMENTS_PATH = `repos/${REPO_FULL}/issues/${PINNED.issue}/comments`;

/** The ONLY local coordinator control-API paths the adapter uses. */
export const BROKER_PATHS = Object.freeze({ guidance: '/api/guidance', state: '/api/state', item: '/api/github-item' });

/** Hidden marker carried by every comment this adapter publishes. Inputs containing it are ignored. */
export const MARKER_HEAD = '<!-- pocol-github-inbox:v1 ';
export const MARKER_RE = /<!-- pocol-github-inbox:v1 key=([0-9a-f]{32}) -->/;

export const COMMAND_RE = /^\/pocol (status|guidance) ([A-Za-z0-9][A-Za-z0-9._-]{2,63})$/;
/** The request-ID part of COMMAND_RE, on its own (used by the operator retry). */
export const REQUEST_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/;
export const BODY_MAX = 4000;
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const POLL_MIN_S = 30;
export const POLL_DEFAULT_S = 60;
export const BACKOFF_MAX_S = 900;
export const PAGE_SIZE = 100;
export const MAX_PAGES_PER_CYCLE = 10;
export const FULL_RESCAN_EVERY = 30;
export const MAX_NEW_PER_CYCLE = 20;
export const MAX_PUBLISH_PER_CYCLE = 10;
export const MAX_TRACKED_COMMENTS = 5000;
/** Item lookups (GET /api/github-item) per cycle, for requests or linked jobs not in the 100-item view. */
export const MAX_LOOKUPS_PER_CYCLE = 10;
/** An uncertain publication is reposted only after this much time AND a later complete scan without its marker. */
export const RECONCILE_MIN_AGE_MS = 120_000;

// ---- delivery outage handling (0.42, I8-07)
/** Attempts in the first delivery epoch; afterwards the request is "stalled" (not failed). */
export const MAX_DELIVERY_ATTEMPTS = 20;
/** Attempts in each later recovery epoch (each started only by an observed healthy coordinator). */
export const RECOVERY_EPOCH_ATTEMPTS = 5;
/** Recovery epochs per request; after that only an explicit operator retry re-enables delivery. */
export const MAX_RECOVERY_EPOCHS = 5;
/** Per-request backoff after the second consecutive failure: base * 2^(n-2), capped. */
export const DELIVERY_BACKOFF_BASE_S = 30;
export const DELIVERY_BACKOFF_MAX_S = 300;
/** Minimum spacing of health reads (GET /api/state) while requests are stalled. */
export const HEALTH_INTERVAL_MS = 300_000;
/** A request undelivered for this long gets ONE temporary transport-blocked reply. */
export const OUTAGE_NOTICE_MS = 600_000;

/** Remote states that can end a request, in rank order. Temporary transport states are not ranked. */
export const STATES = Object.freeze(['received', 'acknowledged', 'running', 'reviewed', 'completed', 'blocked']);
export const FINAL_STATES = Object.freeze(['completed', 'blocked', 'reviewed']);
/** Publication keys of TEMPORARY transport notices: never final, never ranked, never suppress later states. */
export const TEMPORARY_KEYS = Object.freeze(['transportBlocked']);
