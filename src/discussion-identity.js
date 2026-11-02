'use strict';
// RAW M2: only a verified Core principal may authorize a discussion operation.
const crypto = require('node:crypto');
const { now } = require('./db-versioned');
const privatePrincipals = new WeakMap();
const validRoles = new Set(['proposer','challenger','synthesizer','executor','observer']);
const validOwners = new Set(['gpt','claude','workbuddy','human','other']);
const validEfforts = new Set(['low','medium','high','ultra']);
const fail = (why,code=403) => Object.assign(new Error(why),{code});
const tokenDigest = value => crypto.createHash('sha256').update(value,'utf8').digest('hex');
const newId = prefix => prefix + '-' + crypto.randomBytes(12).toString('hex');
function getIdentity(db,id) {
  const r=db.prepare('SELECT * FROM agent_identities WHERE id=?').get(id);
  if (!r || !r.issued_by || r.revoked ||
      !Number.isFinite(Date.parse(r.expires_at)) || Date.parse(r.expires_at)<=Date.now()) {
    throw fail('INV-14: unknown, unverified, revoked or expired identity');
  }
  return r;
}
function authenticatePrincipal(db,{identity_id,token}) {
  if(typeof identity_id!=='string' || typeof token!=='string') {
    throw fail('INV-14: identity possession evidence required');
  }
  const r=getIdentity(db,identity_id);
  const actual=Buffer.from(tokenDigest(token),'hex');
  const expected=Buffer.from(r.token_hash,'hex');
  if(expected.length!==actual.length || !crypto.timingSafeEqual(actual,expected)) {
    throw fail('INV-14: invalid credential');
  }
  const principal=Object.freeze({identity_id:r.id});
  privatePrincipals.set(principal,r.id);
  return principal;
}
function requirePrincipal(db,principal,{discussion_id,roles,owner_types}={}) {
  const id=principal && privatePrincipals.get(principal);
  if(!id)throw fail('INV-14: verified principal required');
  const row=getIdentity(db,id);
  if(discussion_id && row.scope!=='*' && row.scope!==discussion_id) {
    throw fail('INV-14: discussion scope mismatch');
  }
  if(owner_types && !owner_types.includes(row.owner_type)) {
    throw fail('INV-06: human authority required');
  }
  if(roles && row.owner_type!=='human' && !roles.includes(row.role)) {
    throw fail('INV-14: action forbidden for this role');
  }
  return row;
}

function bootstrapHumanIdentity(db,{provisioning_key}={}) {
  const configured=process.env.RAW_CORE_ROOT_PROVISION_KEY;
  if(typeof configured!=='string' || configured.length<32 ||
    typeof provisioning_key!=='string') throw fail('INV-06: operator provisioning required');
  const a=Buffer.from(tokenDigest(configured),'hex');
  const b=Buffer.from(tokenDigest(provisioning_key),'hex');
  if(!crypto.timingSafeEqual(a,b)) throw fail('INV-06: operator proof invalid');
  if(db.prepare("SELECT 1 FROM agent_identities WHERE issued_by='bootstrap'").get()) {
    throw fail('Human root previously provisioned');
  }
  const id=newId('human'),token=crypto.randomBytes(32).toString('hex');
  const issued_at=now(),expires_at=new Date(Date.now()+90*86400000).toISOString();
  db.prepare(
    'INSERT INTO agent_identities(id,owner_type,scope,model,reasoning_effort,role,token_hash,issued_by,issued_at,expires_at,revoked) VALUES(?,?,?,?,?,?,?,?,?,?,0)'
  ).run(id,'human','*','human','high','synthesizer',tokenDigest(token),'bootstrap',issued_at,expires_at);
  return {id,token,expires_at};
}

function issueIdentity(db,{issuer,owner_type,scope,model,reasoning_effort,role,expires_at}) {
  const creator=requirePrincipal(db,issuer,{owner_types:['human']});
  if(!validOwners.has(owner_type) || !validRoles.has(role) ||
    !validEfforts.has(reasoning_effort) || !scope || !model) {
    throw fail('Invalid identity configuration',400);
  }
  if(creator.scope!=='*' && creator.scope!==scope) throw fail('INV-14: issuer scope mismatch');
  const exp=expires_at || new Date(Date.now()+30*86400000).toISOString();
  if(!Number.isFinite(Date.parse(exp)) || Date.parse(exp)<=Date.now() ||
    Date.parse(exp)>Date.now()+90*86400000+1000) {
    throw fail('INV-14: identity expiry invalid',400);
  }
  const id=newId('aid'),token=crypto.randomBytes(32).toString('hex');
  const issued_at=now();
  db.prepare(
    'INSERT INTO agent_identities(id,owner_type,scope,model,reasoning_effort,role,token_hash,issued_by,issued_at,expires_at,revoked) VALUES(?,?,?,?,?,?,?,?,?,?,0)'
  ).run(id,owner_type,scope,model,reasoning_effort,role,tokenDigest(token),creator.id,issued_at,exp);
  return {id,owner_type,scope,model,reasoning_effort,role,token,issued_at,expires_at:exp};
}

function revokeIdentity(db,{revoker,target_identity_id}) {
  const issuer=requirePrincipal(db,revoker),target=getIdentity(db,target_identity_id);
  if(issuer.owner_type!=='human' && issuer.id!==target.id) {
    throw fail('INV-14: cannot revoke another identity');
  }
  if(issuer.scope!=='*' && issuer.scope!==target.scope) {
    throw fail('INV-14: revoker scope mismatch');
  }
  db.prepare('UPDATE agent_identities SET revoked=1 WHERE id=? AND revoked=0').run(target.id);
  return {id:target.id,revoked:true,revoked_by:issuer.id};
}
module.exports={
  bootstrapHumanIdentity,issueIdentity,authenticatePrincipal,requirePrincipal,revokeIdentity,
};
