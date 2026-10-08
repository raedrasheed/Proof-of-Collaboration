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
export const ISSUE_API_URL = `https://api.github.com/repos/${REPO_FULL}/issues/${PINNED.issue}`;
export const ISSUE_HTML_URL = `https://github.com/${REPO_FULL}/issues/${PINNED.issue}`;
/** The ONLY two GitHub REST paths the adapter uses (with a numeric page for the first). */
export const COMMENTS_PATH = `repos/${REPO_FULL}/issues/${PINNED.issue}/comments`;

/** Hidden marker carried by every comment this adapter publishes. Inputs containing it are ignored. */
export const MARKER_HEAD = '<!-- pocol-github-inbox:v1 ';
export const MARKER_RE = /<!-- pocol-github-inbox:v1 key=([0-9a-f]{32}) -->/;

export const COMMAND_RE = /^\/pocol (status|guidance) ([A-Za-z0-9][A-Za-z0-9._-]{2,63})$/;
export const BODY_MAX = 4000;

export const POLL_MIN_S = 30;
export const POLL_DEFAULT_S = 60;
export const BACKOFF_MAX_S = 900;
export const PAGE_SIZE = 100;
export const MAX_PAGES_PER_CYCLE = 10;
export const FULL_RESCAN_EVERY = 30;
export const MAX_NEW_PER_CYCLE = 20;
export const MAX_PUBLISH_PER_CYCLE = 10;
export const MAX_DELIVERY_ATTEMPTS = 20;
export const MAX_TRACKED_COMMENTS = 5000;

/** Remote states, in the only order they can be published. */
export const STATES = Object.freeze(['received', 'acknowledged', 'running', 'reviewed', 'completed', 'blocked']);
export const FINAL_STATES = Object.freeze(['completed', 'blocked', 'reviewed']);
