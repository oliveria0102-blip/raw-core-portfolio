'use strict';
// Versioned, transactional RAW Core schema upgrade. Ordinary open() performs zero DDL.
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const DB_PATH = process.env.RAW_CORE_DB || path.join(DATA_DIR, 'raw-core.db');
const SCHEMA_VERSION = 5;
const DECISION_FIELDS = [
  'id','subject_type','subject_id','decision','evidence_bundle_sha256','decided_by','decided_at'
];
function now() { return new Date().toISOString(); }
function schemaText() {
  return [
    fs.readFileSync(path.join(ROOT, 'schema', 'core.sql'), 'utf8'),
    fs.readFileSync(path.join(ROOT, 'schema', 'm2-security.sql'), 'utf8'),
  ].join('\n');
}
function versionOf(db) {
  return db.prepare('PRAGMA user_version').get().user_version;
}
function tableExists(db, name) {
  return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(name);
}
function columns(db, name) {
  return db.prepare('PRAGMA table_info(' + name + ')').all().map((row) => row.name);
}
function decisionHistory(db) {
  if (!tableExists(db,'human_decisions')) return [];
  return db.prepare('SELECT ' + DECISION_FIELDS.join(',') +
    ' FROM human_decisions ORDER BY id').all();
}
function dropKnownTriggers(db, schema) {
  const desired = new Set([...schema.matchAll(/CREATE TRIGGER IF NOT EXISTS\s+(trg_\w+)/g)]
    .map((m) => m[1]));
  const actual = db.prepare(
    "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'trg_%'"
  ).all();
  for (const {name} of actual) {
    if (!desired.has(name)) throw new Error('Unexpected trigger, migration refused: ' + name);
    db.exec('DROP TRIGGER IF EXISTS "' + name + '"');
  }
}
function migrate(db, schema = schemaText(), {failpoint} = {}) {
  if (versionOf(db) > SCHEMA_VERSION) throw new Error('Database newer than this RAW Core');
  if (versionOf(db) === SCHEMA_VERSION) return {changed:false,version:SCHEMA_VERSION};
  db.exec('BEGIN IMMEDIATE');
  try {
    if (versionOf(db) === SCHEMA_VERSION) {
      db.exec('COMMIT');
      return {changed:false,version:SCHEMA_VERSION};
    }
    const before = decisionHistory(db);
    dropKnownTriggers(db,schema);
    db.exec(schema);
    const oldSql = (db.prepare(
      "SELECT sql FROM sqlite_master WHERE type='table' AND name='human_decisions'"
    ).get() || {}).sql || '';
    if (!oldSql.includes("'discussion'")) {
      dropKnownTriggers(db,schema);
      db.exec('ALTER TABLE human_decisions RENAME TO __raw_legacy_human_decisions');
      const declaration = schema.match(/CREATE TABLE IF NOT EXISTS human_decisions\s*\([\s\S]*?\n\);/);
      if (!declaration) throw new Error('Missing human_decisions create statement');
      db.exec(declaration[0]);
      const fields=DECISION_FIELDS.join(',');
      db.exec('INSERT INTO human_decisions(' + fields + ') SELECT ' + fields +
        ' FROM __raw_legacy_human_decisions');
      db.exec('DROP TABLE __raw_legacy_human_decisions');
    }
    const changes=[
      ['human_decisions','evidence_bundle_id'],['human_decisions','evidence_bundle_version'],
      ['human_decisions','actor_identity_id'],['agent_identities','issued_by'],
      ['evidence_bundles','content'],
    ];
    for (const [table,column] of changes) {
      if (!columns(db,table).includes(column)) {
        db.exec('ALTER TABLE ' + table + ' ADD COLUMN ' + column + ' TEXT');
      }
    }
    dropKnownTriggers(db,schema);
    db.exec(schema);
    if (failpoint==='after_rebuild') throw new Error('INJECTED_MIGRATION_FAILURE');
    if (JSON.stringify(before)!==JSON.stringify(decisionHistory(db))) {
      throw new Error('MIGRATION_HISTORY_MISMATCH: human decisions changed');
    }
    if (db.prepare('PRAGMA foreign_key_check').all().length) {
      throw new Error('MIGRATION_FOREIGN_KEY_FAILURE');
    }
    db.prepare('INSERT INTO schema_migrations(version,description,applied_at) VALUES(?,?,?)')
      .run(SCHEMA_VERSION,'M2 versioned identity, release and decision provenance',now());
    db.exec('PRAGMA user_version=' + SCHEMA_VERSION);
    db.exec('COMMIT');
    return {changed:true,version:SCHEMA_VERSION,decisions_preserved:before.length};
  } catch(e) {
    try {db.exec('ROLLBACK');} catch(_) { /* original error wins */ }
    throw e;
  }
}
function backupBeforeMigration(db, dest) {
  if (!tableExists(db,'messages') && !tableExists(db,'human_decisions')) return null;
  const dir=path.join(path.dirname(dest),'backups');
  fs.mkdirSync(dir,{recursive:true,mode:0o700});
  const file=path.join(dir,'pre-m2-v5-'+now().replace(/[:.]/g,'-')+'-'+
    crypto.randomBytes(4).toString('hex')+'.sqlite');
  // VACUUM INTO captures a consistent WAL-aware snapshot before changing schema.
  db.exec("VACUUM INTO '"+file.replace(/\\/g,'/').replace(/'/g,"''")+"'");
  return file;
}
function open() {
  fs.mkdirSync(path.dirname(DB_PATH),{recursive:true});
  const db=new DatabaseSync(DB_PATH);
  try {
    db.exec('PRAGMA foreign_keys=ON');
    db.exec('PRAGMA recursive_triggers=ON');
    if (versionOf(db)!==SCHEMA_VERSION) {
      if (versionOf(db)>SCHEMA_VERSION) throw new Error('Future schema refused');
      backupBeforeMigration(db,DB_PATH);
      migrate(db);
    }
    db.exec('PRAGMA journal_mode=WAL');
    return db;
  } catch(e) {db.close();throw e;}
}
function appendEvent(db,actor,objectType,objectId,event,details) {
  const at=now();
  db.prepare('INSERT INTO events(at,actor,object_type,object_id,event,details) VALUES(?,?,?,?,?,?)')
    .run(at,actor,objectType,objectId,event,details?JSON.stringify(details):null);
  return at;
}
module.exports = {open,migrate,schemaText,SCHEMA_VERSION,versionOf,appendEvent,now,DB_PATH,ROOT};
