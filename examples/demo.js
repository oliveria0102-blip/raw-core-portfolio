'use strict';
// Entirely synthetic, offline verification. Never opens a production database.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const dir = path.resolve(__dirname, '../work/demo-' + crypto.randomUUID());
fs.mkdirSync(dir, {recursive:true});
process.env.RAW_CORE_DB = path.join(dir, 'synthetic.db');
process.env.RAW_CORE_ROOT_PROVISION_KEY = crypto.randomBytes(32).toString('hex');
const storage = require('../src/db');
const core = require('../src/core');
const identities = require('../src/discussion-identity');
let db = storage.open();
const checks=[];
function check(name,fn){fn();checks.push({name,status:'PASS'});}
const message={message_id:'SYNTHETIC-001',body:'Review a fictional document',idempotency_key:'SYNTHETIC-KEY-001',source:'synthetic-sender'};
try {
 check('message persistence',()=>assert.equal(core.enqueueMessage(db,message).status,'created'));
 check('same payload reuses message',()=>assert.equal(core.enqueueMessage(db,message).status,'reused'));
 check('changed payload conflicts',()=>assert.throws(()=>core.enqueueMessage(db,{...message,body:'changed'}),e=>e.code===409));
 check('stored message is immutable',()=>assert.throws(()=>db.prepare('UPDATE messages SET body=? WHERE id=?').run('changed',message.message_id),/INV-01/));
 check('delivery submission',()=>assert.equal(core.createAttempt(db,{attempt_id:'SYNTHETIC-ATTEMPT',message_id:message.message_id,transport:'synthetic-local'}).status,'submitted'));
 check('visibility requires digest',()=>assert.throws(()=>core.markRemoteVisible(db,{attempt_id:'SYNTHETIC-ATTEMPT'}),e=>e.code===422));
 check('receipt is not execution',()=>assert.equal(core.recordExecution(db,{execution_id:'SYNTHETIC-EXEC',message_id:message.message_id,executor:'synthetic-agent',evidence:{grade:'E3',note:'synthetic acknowledgement only'}}).status,'acknowledged'));
 check('execution requires evidence grade',()=>assert.throws(()=>core.recordExecution(db,{execution_id:'INVALID',message_id:message.message_id,executor:'synthetic-agent'}),e=>e.code===422));
 const decision={id:'SYNTHETIC-DECISION',subject_type:'message',subject_id:message.message_id,decision:'accepted',evidence_bundle_sha256:core.sha256('synthetic review evidence')};
 check('forged principal refused',()=>assert.throws(()=>core.recordHumanDecision(db,{...decision,human_principal:{identity_id:'invented'}}),e=>e.code===403));
 const root=identities.bootstrapHumanIdentity(db,{provisioning_key:process.env.RAW_CORE_ROOT_PROVISION_KEY});
 const principal=identities.authenticatePrincipal(db,{identity_id:root.id,token:root.token});
 check('provisioned synthetic human decision',()=>assert.equal(core.recordHumanDecision(db,{...decision,human_principal:principal}).decision,'accepted'));
 db.close();db=storage.open();
 check('reopen retains one message',()=>assert.equal(db.prepare('SELECT count(*) AS n FROM messages').get().n,1));
 check('SQLite integrity and foreign keys',()=>{assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check,'ok');assert.equal(db.prepare('PRAGMA foreign_key_check').all().length,0)});
 const result={scope:'offline synthetic component checks, not remote agent execution',passed:checks.length,checks};
 fs.writeFileSync(path.join(dir,'result.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));
 console.log('Evidence retained at '+dir);
} finally {db.close();}
