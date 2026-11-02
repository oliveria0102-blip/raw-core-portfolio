-- M2 security extension v5. Load after core.sql, within a single migration transaction.
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY,description TEXT NOT NULL,applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS discussion_release_gates (
  discussion_id TEXT PRIMARY KEY REFERENCES discussions(id),
  expected_count INTEGER NOT NULL CHECK (expected_count >= 2),
  deadline_at TEXT,released_at TEXT,release_reason TEXT,released_by TEXT
);
CREATE TABLE IF NOT EXISTS discussion_expected_proposers (
  discussion_id TEXT NOT NULL REFERENCES discussions(id),
  identity_id TEXT NOT NULL REFERENCES agent_identities(id),
  PRIMARY KEY(discussion_id,identity_id)
);
CREATE TABLE IF NOT EXISTS discussion_disagreements (
  discussion_id TEXT NOT NULL REFERENCES discussions(id),
  disagreement_id TEXT NOT NULL UNIQUE REFERENCES disagreements(id),
  PRIMARY KEY(discussion_id,disagreement_id)
);
CREATE TABLE IF NOT EXISTS disagreement_dispositions (
  id TEXT PRIMARY KEY,discussion_id TEXT NOT NULL REFERENCES discussions(id),
  disagreement_id TEXT NOT NULL REFERENCES disagreements(id),
  synthesis_message_id TEXT NOT NULL REFERENCES messages(id),
  disposition TEXT NOT NULL CHECK (disposition IN ('considered','sustained','rebutted','unresolved')),
  reason TEXT NOT NULL CHECK(length(trim(reason))>0),
  evidence_message_id TEXT REFERENCES messages(id),
  actor_identity_id TEXT NOT NULL REFERENCES agent_identities(id),
  created_at TEXT NOT NULL,UNIQUE(disagreement_id,synthesis_message_id)
);
CREATE TRIGGER IF NOT EXISTS trg_agentid_revocation_only
BEFORE UPDATE ON agent_identities
BEGIN
 SELECT CASE WHEN NEW.id IS NOT OLD.id OR NEW.owner_type IS NOT OLD.owner_type
 OR NEW.scope IS NOT OLD.scope OR NEW.model IS NOT OLD.model
 OR NEW.reasoning_effort IS NOT OLD.reasoning_effort OR NEW.role IS NOT OLD.role
 OR NEW.token_hash IS NOT OLD.token_hash OR NEW.issued_by IS NOT OLD.issued_by
 OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at
 OR OLD.revoked<>0 OR NEW.revoked<>1
 THEN RAISE(ABORT,'INV-14: identity immutable except one-way revoke') END;
END;
CREATE TRIGGER IF NOT EXISTS trg_agentid_revoked_event
AFTER UPDATE OF revoked ON agent_identities WHEN OLD.revoked=0 AND NEW.revoked=1
BEGIN
 INSERT INTO events(at,actor,object_type,object_id,event,details)
 VALUES(datetime('now'),'core','agent_identity',NEW.id,'identity_revoked',NEW.scope);
END;
CREATE TRIGGER IF NOT EXISTS trg_release_no_delete
BEFORE DELETE ON discussion_release_gates BEGIN SELECT RAISE(ABORT,'INV-15: gate immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_release_one_way BEFORE UPDATE ON discussion_release_gates
BEGIN
 SELECT CASE WHEN OLD.released_at IS NOT NULL OR NEW.discussion_id IS NOT OLD.discussion_id
 OR NEW.expected_count IS NOT OLD.expected_count OR NEW.deadline_at IS NOT OLD.deadline_at
 OR NEW.released_at IS NULL OR NEW.release_reason IS NULL OR NEW.released_by IS NULL
 THEN RAISE(ABORT,'INV-15: invalid release transition') END;
END;
CREATE TRIGGER IF NOT EXISTS trg_release_event
AFTER UPDATE OF released_at ON discussion_release_gates
WHEN NEW.released_at IS NOT NULL
BEGIN
 INSERT INTO events(at,actor,object_type,object_id,event,details)
 VALUES(NEW.released_at,NEW.released_by,'proposal_release_gate',NEW.discussion_id,
 'proposals_released',NEW.release_reason);
END;
CREATE TRIGGER IF NOT EXISTS trg_roster_no_update
BEFORE UPDATE ON discussion_expected_proposers BEGIN SELECT RAISE(ABORT,'roster immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_roster_no_delete
BEFORE DELETE ON discussion_expected_proposers BEGIN SELECT RAISE(ABORT,'roster immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_disc_disagree_no_update
BEFORE UPDATE ON discussion_disagreements BEGIN SELECT RAISE(ABORT,'disagreement link immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_disc_disagree_no_delete
BEFORE DELETE ON discussion_disagreements BEGIN SELECT RAISE(ABORT,'disagreement link immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_disposition_no_update
BEFORE UPDATE ON disagreement_dispositions BEGIN SELECT RAISE(ABORT,'disposition immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_disposition_no_delete
BEFORE DELETE ON disagreement_dispositions BEGIN SELECT RAISE(ABORT,'disposition immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_disposition_check BEFORE INSERT ON disagreement_dispositions
BEGIN
 SELECT CASE WHEN NOT EXISTS(
 SELECT 1 FROM discussion_disagreements x WHERE x.discussion_id=NEW.discussion_id
 AND x.disagreement_id=NEW.disagreement_id)
 OR NOT EXISTS(SELECT 1 FROM discussion_members m WHERE m.discussion_id=NEW.discussion_id
 AND m.message_id=NEW.synthesis_message_id AND m.role='synthesis')
 OR (NEW.evidence_message_id IS NOT NULL AND NOT EXISTS(
 SELECT 1 FROM discussion_members m WHERE m.discussion_id=NEW.discussion_id
 AND m.message_id=NEW.evidence_message_id))
 THEN RAISE(ABORT,'INV-08: invalid disposition') END;
END;
CREATE TRIGGER IF NOT EXISTS trg_disposition_event
AFTER INSERT ON disagreement_dispositions
BEGIN
 INSERT INTO events(at,actor,object_type,object_id,event,details)
 VALUES(NEW.created_at,NEW.actor_identity_id,'disagreement_disposition',NEW.id,
 'disposition_'||NEW.disposition,NEW.disagreement_id||'|'||NEW.reason);
END;
CREATE TRIGGER IF NOT EXISTS trg_inv16_decision_bundle
BEFORE INSERT ON human_decisions WHEN NEW.subject_type='discussion'
BEGIN
 SELECT CASE WHEN NOT EXISTS(
 SELECT 1 FROM evidence_bundles e WHERE e.id=NEW.evidence_bundle_id
 AND e.version=NEW.evidence_bundle_version AND e.content_sha256=NEW.evidence_bundle_sha256
 AND e.subject_type='discussion' AND e.subject_id=NEW.subject_id)
 OR NOT EXISTS(SELECT 1 FROM agent_identities a WHERE a.id=NEW.actor_identity_id
 AND a.owner_type='human' AND a.revoked=0 AND (a.scope=NEW.subject_id OR a.scope='*')
 AND datetime(a.expires_at)>datetime('now'))
 THEN RAISE(ABORT,'INV-06/07/16: decision provenance invalid') END;
END;
CREATE TRIGGER IF NOT EXISTS trg_mref_relation_matrix
BEFORE INSERT ON message_refs
BEGIN
 SELECT CASE WHEN NOT EXISTS(
 SELECT 1 FROM discussion_members s JOIN discussion_members t ON t.discussion_id=s.discussion_id
 WHERE s.message_id=NEW.source_id AND t.message_id=NEW.target_id)
 THEN RAISE(ABORT,'M2: cross-discussion reference') END;
 SELECT CASE WHEN NOT (
 (NEW.relation='answers' AND (SELECT kind FROM messages WHERE id=NEW.source_id)='proposal'
 AND (SELECT kind FROM messages WHERE id=NEW.target_id)='question')
 OR (NEW.relation IN ('challenges','disputes') AND (SELECT kind FROM messages WHERE id=NEW.source_id)='challenge'
 AND (SELECT kind FROM messages WHERE id=NEW.target_id)='proposal')
 OR (NEW.relation='verifies' AND (SELECT kind FROM messages WHERE id=NEW.source_id)='verification'
 AND (SELECT kind FROM messages WHERE id=NEW.target_id) IN ('proposal','challenge'))
 OR (NEW.relation='synthesizes' AND (SELECT kind FROM messages WHERE id=NEW.source_id)='synthesis'
 AND (SELECT kind FROM messages WHERE id=NEW.target_id) IN ('question','proposal','challenge','verification'))
 ) THEN RAISE(ABORT,'M2: reference kind mismatch') END;
END;
CREATE TRIGGER IF NOT EXISTS trg_disc_status_order
BEFORE UPDATE OF status ON discussions WHEN NEW.status IS NOT OLD.status
BEGIN
 SELECT CASE WHEN NOT ((OLD.status='open' AND NEW.status IN ('synthesized','abandoned'))
 OR (OLD.status='synthesized' AND NEW.status IN ('decided','abandoned')))
 THEN RAISE(ABORT,'M2: invalid status transition') END;
END;
