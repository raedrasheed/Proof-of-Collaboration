# Issue 8: GitHub-to-local transport acceptance

Connection: NOT ACTIVE until actual end-to-end proof. This adapter is a separate explicitly requested coordinator transport improvement; LP3 author dispatch remains blocked and must not be retried. Existing broker, session, pause and author/review controls are unchanged.

G0: fixed repository/issue/owner login+numericID; existing local gh authentication only, no token export or arbitrary command/endpoint.
G1: explicit status/guidance commands only; reject other actors/threads/bots/malformed/edited replays and linked-content execution.
G2: durable comment/local-item/result IDs and digests; restart/delivery/publication uncertainty reconciles idempotency/markers, bounded pagination and retries/backoff, one transport process.
G3: delivery never equated with local acknowledgement; adapter never calls reviewer/author/pause/approval endpoints. Actual host acknowledgement/result required.
G4: received/running/reviewed/completed/blocked messages correspond to observed evidence; status-only completion is distinguished from project completion. Arabic dashboard displays actual guidance/receipt and agent responses through existing broker.
G5: secrets/private URLs/session fields/local paths/raw transcripts excluded from public replies and logs; output allowlists and redaction tested.
G6: meaningful independent unit/HTTP tests plus real harmless owner-account comment -> existing local broker -> actual host acknowledgement -> GitHub result. Duplicate delivery and fresh-process restart must not produce another local item or result.
G7: exact supported config/start/stop/credential/owner guidance procedure and remaining local actions published directly on issue8. Root marks verified only after G0-G6 proof; periodic adapter is transport, not a duplicate agent loop. No production/funds/purchases/destructive migration/merge.

Claude authors isolated transport0.40 files; Codex independently reviews/tests. Corrections are separate fresh revisions. All progress, blockers and actual results go directly to issue8; a draft PR holds reviewable code/evidence.
