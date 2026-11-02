-- RAW Core schema v0.2 (protocol v0)
-- 四对象 + append-only 事件 + 收件箱回执 + 分歧/授权（INV-08/09 结构落地）
-- v0.2: 按第三方（CC 只读审查 + GPT-6 审查）补齐证据门槛 CHECK、决定/回执追加触发器

PRAGMA foreign_keys = ON;
-- REPLACE 内部 DELETE 需此开关才会触发 INV-01 的 DELETE 触发器
PRAGMA recursive_triggers = ON;

CREATE TABLE IF NOT EXISTS messages (
  id              TEXT PRIMARY KEY,      -- message_id
  kind            TEXT NOT NULL,         -- 'task' | 'discussion' | 'probe' | ...
  body            TEXT NOT NULL,        -- frozen content, INV-01 immutable
  body_sha256     TEXT NOT NULL,        -- payload digest (frozen envelope)
  idempotency_key TEXT NOT NULL UNIQUE, -- INV-02: one key one body
  source          TEXT NOT NULL,         -- authenticated sender
  created_at      TEXT NOT NULL          -- Core server time (authoritative clock)
);

CREATE TABLE IF NOT EXISTS delivery_attempts (
  id               TEXT PRIMARY KEY,     -- attempt_id
  message_id       TEXT NOT NULL REFERENCES messages(id),
  transport        TEXT NOT NULL,         -- 'web-gpt-bridge' | 'claude-mcp' | ...
  status           TEXT NOT NULL CHECK (status IN
                     ('submitted','remote_visible','acknowledged','failed','timed_out','unknown')),
  submitted_at     TEXT,
  remote_visible_at TEXT,
  visible_sha256   TEXT,                  -- observed transcript digest (rules versioned)
  error            TEXT,
  -- INV-04: 标记送达必须有可见性证据，库层拒绝无证据的 remote_visible
  CHECK (status <> 'remote_visible' OR visible_sha256 IS NOT NULL),
  UNIQUE (message_id, transport, submitted_at)  -- INV-03: attempts append, never overwrite
);

CREATE TABLE IF NOT EXISTS executions (
  id             TEXT PRIMARY KEY,        -- execution_id
  message_id     TEXT NOT NULL REFERENCES messages(id),
  executor       TEXT NOT NULL,           -- provider + stable_ref + account_scope
  model_identity TEXT,                    -- actual model if known (client != model)
  status         TEXT NOT NULL CHECK (status IN
                   ('unobserved','acknowledged','executed','result_recorded',
                    'review_required','not_proven')),
  evidence       TEXT NOT NULL,           -- JSON: evidence refs + E-grades
  result_sha256  TEXT,
  recorded_at    TEXT NOT NULL,
  -- INV-05: 标记 executed 必须有有效 JSON 证据且含 grade 字段
  CHECK (status <> 'executed'
         OR (json_valid(evidence) AND evidence LIKE '%grade%'))
);

CREATE TABLE IF NOT EXISTS human_decisions (
  id                    TEXT PRIMARY KEY,
  subject_type          TEXT NOT NULL CHECK (subject_type IN ('execution','message','discussion')),
  subject_id            TEXT NOT NULL,
  decision              TEXT NOT NULL CHECK (decision IN ('accepted','rejected')),
  evidence_bundle_sha256 TEXT NOT NULL,  -- INV-07
  evidence_bundle_id TEXT,
  evidence_bundle_version TEXT,
  actor_identity_id TEXT,
  -- INV-06: 库层拒绝 Agent 冒充人类接受
  decided_by            TEXT NOT NULL CHECK (decided_by = 'user'),
  decided_at            TEXT NOT NULL
);

-- INV-08: 未解决异议保留（append-only，禁止原地改写或删除）
CREATE TABLE IF NOT EXISTS disagreements (
  id            TEXT PRIMARY KEY,
  subject_type  TEXT NOT NULL,
  subject_id    TEXT NOT NULL,
  claim         TEXT NOT NULL,
  counter_claim TEXT,
  status        TEXT NOT NULL CHECK (status IN ('open','resolved','unresolved')),
  created_at    TEXT NOT NULL
);

-- INV-09: 授权范围与预算（越界执行须停止并升级人工）
CREATE TABLE IF NOT EXISTS authorizations (
  id                      TEXT PRIMARY KEY,
  subject_type            TEXT NOT NULL,
  subject_id              TEXT NOT NULL,
  scope                   TEXT NOT NULL,
  budget                  TEXT,
  requires_human_approval INTEGER NOT NULL DEFAULT 1,
  created_at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inbox_receipts (
  receipt_id  TEXT PRIMARY KEY,
  message_id  TEXT NOT NULL,
  sender      TEXT NOT NULL,
  body        TEXT NOT NULL,
  body_sha256 TEXT NOT NULL,
  received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  at          TEXT NOT NULL,
  actor       TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id   TEXT NOT NULL,
  event       TEXT NOT NULL,
  details     TEXT,                       -- JSON evidence refs
  details_sha256 TEXT
);

-- INV-01: message body frozen after insert (UPDATE and DELETE both blocked;
-- DELETE also blocks INSERT OR REPLACE, which internally does DELETE+INSERT)
CREATE TRIGGER IF NOT EXISTS trg_message_immutable
BEFORE UPDATE ON messages
BEGIN
  SELECT RAISE(ABORT, 'INV-01: message body is frozen');
END;

CREATE TRIGGER IF NOT EXISTS trg_message_no_delete
BEFORE DELETE ON messages
BEGIN
  SELECT RAISE(ABORT, 'INV-01: messages cannot be deleted or replaced');
END;

-- append-only events: no update, no delete (replay integrity)
CREATE TRIGGER IF NOT EXISTS trg_event_no_update
BEFORE UPDATE ON events
BEGIN
  SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_event_no_delete
BEFORE DELETE ON events
BEGIN
  SELECT RAISE(ABORT, 'events are append-only');
END;

-- delivery attempts append-only (INV-03)
CREATE TRIGGER IF NOT EXISTS trg_attempt_no_update
BEFORE UPDATE ON delivery_attempts
BEGIN
  SELECT RAISE(ABORT, 'INV-03: old attempts cannot be overwritten; append a new row');
END;

CREATE TRIGGER IF NOT EXISTS trg_attempt_no_delete
BEFORE DELETE ON delivery_attempts
BEGIN
  SELECT RAISE(ABORT, 'INV-03: attempts cannot be deleted');
END;

-- INV-07: 已作出的人工决定不可原地改写（对照 messages/attempts/events）
CREATE TRIGGER IF NOT EXISTS trg_decision_no_update
BEFORE UPDATE ON human_decisions
BEGIN
  SELECT RAISE(ABORT, 'INV-07: decisions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_decision_no_delete
BEFORE DELETE ON human_decisions
BEGIN
  SELECT RAISE(ABORT, 'INV-07: decisions are append-only');
END;

-- INV-08: 异议记录追加，禁止静默关闭
CREATE TRIGGER IF NOT EXISTS trg_disagreement_no_update
BEFORE UPDATE ON disagreements
BEGIN
  SELECT RAISE(ABORT, 'INV-08: disagreements are append-only; resolve by new row');
END;

CREATE TRIGGER IF NOT EXISTS trg_disagreement_no_delete
BEFORE DELETE ON disagreements
BEGIN
  SELECT RAISE(ABORT, 'INV-08: disagreements are append-only');
END;

-- 回执追加（receipt_id 身份语义：不可改写历史回执）
CREATE TRIGGER IF NOT EXISTS trg_receipt_no_update
BEFORE UPDATE ON inbox_receipts
BEGIN
  SELECT RAISE(ABORT, 'receipts are append-only');
END;

-- 库层强制"状态迁移必须追加事件"（协议 §1）：任何对象写入都自动落事件，
-- 使"真实状态可由事件重放重建"不再依赖应用层自觉
CREATE TRIGGER IF NOT EXISTS trg_attempt_event
AFTER INSERT ON delivery_attempts
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (COALESCE(NEW.submitted_at, datetime('now')), 'core', 'delivery_attempt',
          NEW.id, 'attempt_' || NEW.status, NEW.error);
END;

CREATE TRIGGER IF NOT EXISTS trg_execution_event
AFTER INSERT ON executions
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (NEW.recorded_at, 'core', 'execution', NEW.id,
          'execution_' || NEW.status, NEW.evidence);
END;

CREATE TRIGGER IF NOT EXISTS trg_decision_event
AFTER INSERT ON human_decisions
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (NEW.decided_at, NEW.decided_by, 'human_decision', NEW.id,
          'decision_' || NEW.decision, NEW.evidence_bundle_sha256);
END;

CREATE TRIGGER IF NOT EXISTS trg_disagreement_event
AFTER INSERT ON disagreements
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (NEW.created_at, 'core', 'disagreement', NEW.id,
          'disagreement_' || NEW.status, NEW.claim);
END;

CREATE TRIGGER IF NOT EXISTS trg_receipt_event
AFTER INSERT ON inbox_receipts
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (NEW.received_at, NEW.sender, 'receipt', NEW.receipt_id,
          'receipt_recorded', NEW.body_sha256);
END;

CREATE TRIGGER IF NOT EXISTS trg_receipt_no_delete
BEFORE DELETE ON inbox_receipts
BEGIN
  SELECT RAISE(ABORT, 'receipts are append-only');
END;

-- ============================================================
-- M2 Discussion Loop (schema v0.4) — appended after M1
-- 设计见 docs/MILESTONE-M2.md §三；INV-11..16
-- NOTE: INV-16 (HumanDecision must reference evidence_bundles) is enforced
--       at application layer first; its DB trigger is deferred until M2 live-run validates it.
-- ============================================================

-- 讨论对象（mode 列支撑 Goal 模式常驻 §9.2）
CREATE TABLE IF NOT EXISTS discussions (
  id         TEXT PRIMARY KEY,
  title      TEXT NOT NULL,
  status     TEXT NOT NULL CHECK (status IN ('open','synthesized','decided','abandoned')),
  mode       TEXT NOT NULL DEFAULT 'normal' CHECK (mode IN ('normal','goal')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS discussion_members (
  discussion_id TEXT NOT NULL REFERENCES discussions(id),
  message_id    TEXT NOT NULL REFERENCES messages(id),
  role          TEXT NOT NULL CHECK (role IN ('question','proposal','challenge','verification','synthesis')),
  joined_at     TEXT NOT NULL,
  PRIMARY KEY (discussion_id, message_id)
);

CREATE TABLE IF NOT EXISTS message_refs (
  id         TEXT PRIMARY KEY,
  source_id  TEXT NOT NULL REFERENCES messages(id),
  target_id  TEXT NOT NULL REFERENCES messages(id),
  relation   TEXT NOT NULL CHECK (relation IN ('answers','challenges','verifies','synthesizes','disputes')),
  created_at TEXT NOT NULL
);

-- 服务端签发身份令牌（INV-14 前提）：替代客户端 authenticated_human 布尔值
-- 扩展 model / reasoning_effort / role 支撑模型与思考强度选择（§9.4）
CREATE TABLE IF NOT EXISTS agent_identities (
  id               TEXT PRIMARY KEY,
  owner_type       TEXT NOT NULL CHECK (owner_type IN ('gpt','claude','workbuddy','human','other')),
  scope            TEXT NOT NULL,
  model            TEXT NOT NULL,
  reasoning_effort TEXT NOT NULL CHECK (reasoning_effort IN ('low','medium','high','ultra')),
  role             TEXT NOT NULL CHECK (role IN ('proposer','challenger','synthesizer','executor','observer')),
  token_hash       TEXT NOT NULL,
  issued_by        TEXT,
  issued_at        TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  revoked          INTEGER NOT NULL DEFAULT 0
);

-- 独立提案封存（INV-15 前提）：防锚定的时序隔离
CREATE TABLE IF NOT EXISTS proposal_seals (
  discussion_id TEXT NOT NULL REFERENCES discussions(id),
  message_id    TEXT NOT NULL REFERENCES messages(id),
  sealed_at     TEXT NOT NULL,
  release_at    TEXT NOT NULL,
  released_by   TEXT,
  PRIMARY KEY (discussion_id, message_id)
);

-- 证据 bundle 版本化（INV-16 前提）
CREATE TABLE IF NOT EXISTS evidence_bundles (
  id              TEXT PRIMARY KEY,
  version         TEXT NOT NULL,
  subject_type    TEXT NOT NULL,
  subject_id      TEXT NOT NULL,
  content_sha256  TEXT NOT NULL,
  content         TEXT,
  signed_by       TEXT NOT NULL REFERENCES agent_identities(id),
  created_at      TEXT NOT NULL
);

-- ---- M2 新表 append-only 触发器 ----
-- 仅允许 status / mode 列变更；title/id/created_at 不可变
CREATE TRIGGER IF NOT EXISTS trg_discussion_no_update BEFORE UPDATE ON discussions
BEGIN
  SELECT CASE
    WHEN NEW.title <> OLD.title THEN RAISE(ABORT,'discussions: title is immutable')
    WHEN NEW.id <> OLD.id THEN RAISE(ABORT,'discussions: id is immutable')
    WHEN NEW.created_at <> OLD.created_at THEN RAISE(ABORT,'discussions: created_at is immutable')
    ELSE 0 END;
END;
CREATE TRIGGER IF NOT EXISTS trg_discussion_no_delete BEFORE DELETE ON discussions
BEGIN SELECT RAISE(ABORT,'discussions are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_dmember_no_update BEFORE UPDATE ON discussion_members
BEGIN SELECT RAISE(ABORT,'discussion_members are append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_dmember_no_delete BEFORE DELETE ON discussion_members
BEGIN SELECT RAISE(ABORT,'discussion_members are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_mref_no_update BEFORE UPDATE ON message_refs
BEGIN SELECT RAISE(ABORT,'message_refs are append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_mref_no_delete BEFORE DELETE ON message_refs
BEGIN SELECT RAISE(ABORT,'message_refs are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_agentid_no_delete BEFORE DELETE ON agent_identities
BEGIN SELECT RAISE(ABORT,'agent_identities are append-only (revoke, do not delete)'); END;

CREATE TRIGGER IF NOT EXISTS trg_pseal_no_update BEFORE UPDATE ON proposal_seals
BEGIN SELECT RAISE(ABORT,'proposal_seals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_pseal_no_delete BEFORE DELETE ON proposal_seals
BEGIN SELECT RAISE(ABORT,'proposal_seals are append-only'); END;

CREATE TRIGGER IF NOT EXISTS trg_ebundle_no_update BEFORE UPDATE ON evidence_bundles
BEGIN SELECT RAISE(ABORT,'evidence_bundles are append-only'); END;
CREATE TRIGGER IF NOT EXISTS trg_ebundle_no_delete BEFORE DELETE ON evidence_bundles
BEGIN SELECT RAISE(ABORT,'evidence_bundles are append-only'); END;

-- ---- INV-11：synthesis 必须引用 >=1 条 message ----
CREATE TRIGGER IF NOT EXISTS trg_inv11_synthesis_refs
BEFORE UPDATE OF status ON discussions
WHEN NEW.status = 'synthesized' AND OLD.status <> 'synthesized'
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM discussion_members dm WHERE dm.discussion_id=NEW.id AND dm.role='synthesis'
  ) OR EXISTS (
    SELECT 1 FROM discussion_members dm WHERE dm.discussion_id=NEW.id AND dm.role='synthesis'
      AND NOT EXISTS (
        SELECT 1 FROM message_refs r WHERE r.source_id=dm.message_id AND r.relation='synthesizes'
      )
  ) THEN RAISE(ABORT, 'INV-11: synthesis must include evidence references') END;
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM discussion_disagreements dd WHERE dd.discussion_id=NEW.id
      AND NOT EXISTS (
        SELECT 1 FROM disagreement_dispositions x
          JOIN discussion_members dm ON dm.message_id=x.synthesis_message_id
        WHERE dm.discussion_id=NEW.id AND dm.role='synthesis'
          AND x.disagreement_id=dd.disagreement_id
      )
  ) THEN RAISE(ABORT, 'INV-08: each disagreement must have a disposition') END;
END;

-- ---- INV-12：proposal 不得引用 proposal（防锚定） ----
CREATE TRIGGER IF NOT EXISTS trg_inv12_proposal_no_proposal
BEFORE INSERT ON message_refs
WHEN (SELECT kind FROM messages WHERE id = NEW.source_id) = 'proposal'
BEGIN
  SELECT CASE WHEN NEW.relation <> 'answers'
    OR (SELECT kind FROM messages WHERE id = NEW.target_id) <> 'question'
    THEN RAISE(ABORT, 'INV-12: proposal may only answers->question, never reference another proposal') END;
END;

-- ---- INV-13：discussions 状态/模式迁移必须留事件 ----
CREATE TRIGGER IF NOT EXISTS trg_inv13_discussion_event
AFTER UPDATE ON discussions
WHEN NEW.status <> OLD.status OR NEW.mode <> OLD.mode
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (datetime('now'), 'core', 'discussion', NEW.id,
          'discussion_transition', 'status:' || NEW.status || '|mode:' || NEW.mode);
END;

-- ---- INV-14：讨论消息的来源必须是服务端签发的有效身份（M1 通用消息不进讨论，不受影响） ----
-- 注意：expires_at 为 ISO8601（含 'T' 与 'Z'），必须用 datetime(replace(...,'Z','')) 归一后比较，
-- 否则 'T'/空格 与 'Z' 差异会导致字符串比较误判过期。
CREATE TRIGGER IF NOT EXISTS trg_inv14_dmember_identity
BEFORE INSERT ON discussion_members
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM agent_identities ai
    JOIN messages m ON m.source = ai.id
    WHERE m.id = NEW.message_id
      AND ai.revoked = 0
      AND datetime(replace(ai.expires_at,'Z','')) > datetime('now')
      AND (ai.scope=NEW.discussion_id OR ai.scope='*')
      AND (ai.owner_type='human' OR
        (NEW.role IN ('question','proposal') AND ai.role='proposer') OR
        (NEW.role='challenge' AND ai.role='challenger') OR
        (NEW.role='verification' AND ai.role IN ('challenger','executor')) OR
        (NEW.role='synthesis' AND ai.role='synthesizer'))
  ) THEN RAISE(ABORT, 'INV-14: discussion message source must be a valid, unrevoked, unexpired server-issued identity') END;
END;

-- ---- INV-15：proposal_seals 发布事件（封存期隔离由 Core 读取层 enforce） ----
CREATE TRIGGER IF NOT EXISTS trg_inv15_seal_event
AFTER INSERT ON proposal_seals
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (NEW.sealed_at, 'core', 'proposal_seal', NEW.message_id, 'proposal_sealed', NEW.discussion_id);
END;

-- ---- 新表写入自动落事件（协议 §1：状态迁移必须追加事件） ----
CREATE TRIGGER IF NOT EXISTS trg_discussion_event
AFTER INSERT ON discussions
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (NEW.created_at, 'core', 'discussion', NEW.id, 'discussion_open', NEW.title);
END;

CREATE TRIGGER IF NOT EXISTS trg_dmember_event
AFTER INSERT ON discussion_members
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (NEW.joined_at, 'core', 'discussion_member', NEW.message_id, 'member_join', NEW.discussion_id || '|' || NEW.role);
END;

CREATE TRIGGER IF NOT EXISTS trg_mref_event
AFTER INSERT ON message_refs
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (NEW.created_at, 'core', 'message_ref', NEW.id, 'ref_' || NEW.relation, NEW.source_id || '->' || NEW.target_id);
END;

CREATE TRIGGER IF NOT EXISTS trg_agentid_event
AFTER INSERT ON agent_identities
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (NEW.issued_at, NEW.owner_type, 'agent_identity', NEW.id, 'identity_issued', NEW.scope || '|' || NEW.model || '|' || NEW.reasoning_effort);
END;

CREATE TRIGGER IF NOT EXISTS trg_ebundle_event
AFTER INSERT ON evidence_bundles
BEGIN
  INSERT INTO events (at, actor, object_type, object_id, event, details)
  VALUES (NEW.created_at, NEW.signed_by, 'evidence_bundle', NEW.id, 'bundle_created', NEW.version || '|' || NEW.content_sha256);
END;
