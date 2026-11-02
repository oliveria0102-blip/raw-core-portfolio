'use strict';
// RAW Core — invariant-enforcing operations (protocol v0)
const crypto = require('node:crypto');
const { appendEvent, now } = require('./db');

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// Message → QUEUED (evidence: server persistence + id + digest + authenticated source)
function enqueueMessage(db, { message_id, kind, body, idempotency_key, source }) {
  if (!message_id || typeof message_id !== 'string' || message_id.length > 96) {
    throw Object.assign(new Error('invalid message_id'), { code: 400 });
  }
  if (typeof body !== 'string' || !body) {
    throw Object.assign(new Error('invalid body'), { code: 400 });
  }
  if (!idempotency_key || !source) {
    throw Object.assign(new Error('idempotency_key and source required'), { code: 400 });
  }
  const digest = sha256(body);
  const prior = db
    .prepare('SELECT id, body_sha256 FROM messages WHERE idempotency_key = ?')
    .get(idempotency_key);
  if (prior) {
    // INV-02: same key different body is a conflict; same key same body is a reuse
    if (prior.body_sha256 !== digest) {
      throw Object.assign(new Error('INV-02 idempotency conflict'), { code: 409 });
    }
    return { status: 'reused', message_id: prior.id };
  }
  const at = now();
  db.prepare(
    `INSERT INTO messages (id, kind, body, body_sha256, idempotency_key, source, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(message_id, kind || 'generic', body, digest, idempotency_key, source, at);
  appendEvent(db, source, 'message', message_id, 'queued', {
    body_sha256: digest,
  });
  return { status: 'created', message_id, body_sha256: digest, queued_at: at };
}

// DeliveryAttempt → SUBMITTED (append-only, INV-03 enforced by trigger)
function createAttempt(db, { attempt_id, message_id, transport }) {
  const at = now();
  db.prepare(
    `INSERT INTO delivery_attempts (id, message_id, transport, status, submitted_at)
     VALUES (?, ?, ?, 'submitted', ?)`
  ).run(attempt_id, message_id, transport, at);
  appendEvent(db, 'core', 'delivery_attempt', attempt_id, 'submitted', {
    message_id,
    transport,
  });
  return { attempt_id, status: 'submitted', submitted_at: at };
}

// DeliveryAttempt → REMOTE_VISIBLE (requires visible digest per evidence table)
function markRemoteVisible(db, { attempt_id, visible_sha256 }) {
  if (!visible_sha256) {
    throw Object.assign(new Error('REMOTE_VISIBLE requires visible_sha256 (evidence table)'), {
      code: 422,
    });
  }
  const at = now();
  // INV-03: append a NEW row carrying the visible state (old row immutable)
  const row = db
    .prepare('SELECT message_id, transport FROM delivery_attempts WHERE id = ?')
    .get(attempt_id);
  if (!row) throw Object.assign(new Error('attempt not found'), { code: 404 });
  const nextId = attempt_id + ':visible:' + at.replace(/[:.]/g, '-');
  db.prepare(
    `INSERT INTO delivery_attempts (id, message_id, transport, status, submitted_at,
       remote_visible_at, visible_sha256)
     VALUES (?, ?, ?, 'remote_visible', NULL, ?, ?)`
  ).run(nextId, row.message_id, row.transport, at, visible_sha256);
  // 注意：不可再对该行执行任何 UPDATE——INV-03 触发器会拒绝（含 no-op 更新）
  appendEvent(db, 'core', 'delivery_attempt', nextId, 'remote_visible', {
    parent_attempt: attempt_id,
    visible_sha256,
  });
  return { attempt_id: nextId, status: 'remote_visible', at };
}

// Execution records (E-graded; no evidence → stays unobserved/not_proven, INV-04/05)
function recordExecution(db, { execution_id, message_id, executor, evidence, model_identity }) {
  if (!evidence || !evidence.grade) {
    throw Object.assign(new Error('execution requires evidence grade'), { code: 422 });
  }
  const at = now();
  db.prepare(
    `INSERT INTO executions (id, message_id, executor, model_identity, status, evidence, recorded_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    execution_id,
    message_id,
    executor,
    model_identity || null,
    // 协议 E 分级→状态映射：E3=客户端确认回执，E4=真实执行验证，其余保持未证明
    evidence.grade === 'E4' ? 'executed' : evidence.grade === 'E3' ? 'acknowledged' : 'unobserved',
    JSON.stringify(evidence),
    at
  );
  const status =
    evidence.grade === 'E4' ? 'executed' : evidence.grade === 'E3' ? 'acknowledged' : 'unobserved';
  appendEvent(db, 'core', 'execution', execution_id, 'recorded', {
    grade: evidence.grade,
    message_id,
  });
  return { execution_id, status };
}

// HumanDecision (INV-06/07)
// human_principal 是 Core 验证过的持有性对象；不能以布尔值冒充人工授权。
function recordHumanDecision(
  db,
  { id, subject_type, subject_id, decision, evidence_bundle_sha256, human_principal }
) {
  const human = require('./discussion-identity').requirePrincipal(
    db, human_principal, { owner_types: ['human'] }
  );
  if (subject_type === 'discussion') {
    throw Object.assign(new Error('INV-06: use discussion-specific decision API'), {code: 400});
  }
  if (!human || !['message','execution'].includes(subject_type)) {
    throw Object.assign(
      new Error('INV-06: decision requires an authenticated human session'),
      { code: 403 }
    );
  }
  if (!/^[0-9a-f]{64}$/.test(String(evidence_bundle_sha256 || ''))) {
    throw Object.assign(new Error('INV-07: decision must bind evidence bundle sha256'), {
      code: 422,
    });
  }
  if (!['accepted','rejected'].includes(decision)) throw Object.assign(
    new Error('INV-07: decision type invalid'), {code: 422}
  );
  const table = subject_type === 'message' ? 'messages' : 'executions';
  if (!db.prepare('SELECT 1 FROM ' + table + ' WHERE id=?').get(subject_id)) {
    throw Object.assign(new Error('INV-07: decision target missing'), {code: 404});
  }
  db.exec('BEGIN IMMEDIATE');
  try {
  const at = now();
  db.prepare(
    `INSERT INTO human_decisions
       (id, subject_type, subject_id, decision, evidence_bundle_sha256, actor_identity_id, decided_by, decided_at)
     VALUES (?, ?, ?, ?, ?, ?, 'user', ?)`
  ).run(id, subject_type, subject_id, decision, evidence_bundle_sha256, human.id, at);
  // The SQLite trigger writes the audit event inside the same transaction.
  db.exec('COMMIT');
  return { id, decision, decided_at: at };
  } catch(e) {
    try { db.exec('ROLLBACK'); } catch(_) {}
    throw e;
  }
}

module.exports = {
  sha256,
  enqueueMessage,
  createAttempt,
  markRemoteVisible,
  recordExecution,
  recordHumanDecision,
};
