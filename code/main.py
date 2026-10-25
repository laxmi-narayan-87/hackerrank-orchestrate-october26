#!/usr/bin/env python3
"""Deletion audit baseline, offline and non-destructive."""
from __future__ import annotations
import argparse,csv,hashlib,json,re,sqlite3,sys,shutil,subprocess
from dataclasses import dataclass
from datetime import datetime,timezone
from pathlib import Path
from typing import Any
HEADER=['case_id','deletion_status','steps_json'];PHASE={'FINDING':0,'REMEDIATION':1,'VERIFICATION':2};ORDER={'REPORT_REMAINING_RECORD':0,'REPORT_EXPOSED_PII':1,'REPORT_ACTIVE_DATA_FLOW':2,'REPORT_RESTORE_RISK':3,'DISABLE_DATA_FLOW':0,'BLOCK_RESTORE':1,'DELETE_RECORD':2,'REDACT_RECORD':3,'ANONYMIZE_RECORD':4,'VERIFY_RECORD_ABSENT':0,'VERIFY_RECORD_PRESENT':1,'VERIFY_RECORD_REDACTED':2,'VERIFY_RECORD_ANONYMIZED':3,'VERIFY_DATA_FLOW_DISABLED':4,'VERIFY_RESTORE_BLOCKED':5}
OP={'REPORT_REMAINING_RECORD':('FINDING','PRESENT'),'REPORT_EXPOSED_PII':('FINDING','PRESENT'),'REPORT_ACTIVE_DATA_FLOW':('FINDING','ACTIVE'),'REPORT_RESTORE_RISK':('FINDING','ACTIVE'),'DISABLE_DATA_FLOW':('REMEDIATION','DISABLED'),'BLOCK_RESTORE':('REMEDIATION','BLOCKED'),'DELETE_RECORD':('REMEDIATION','ABSENT'),'REDACT_RECORD':('REMEDIATION','REDACTED'),'ANONYMIZE_RECORD':('REMEDIATION','ANONYMIZED'),'VERIFY_RECORD_ABSENT':('VERIFICATION','ABSENT'),'VERIFY_RECORD_PRESENT':('VERIFICATION','PRESENT'),'VERIFY_RECORD_REDACTED':('VERIFICATION','REDACTED'),'VERIFY_RECORD_ANONYMIZED':('VERIFICATION','ANONYMIZED'),'VERIFY_DATA_FLOW_DISABLED':('VERIFICATION','DISABLED'),'VERIFY_RESTORE_BLOCKED':('VERIFICATION','BLOCKED')}
def dt(v):
 if not v:return None
 try:
  v=v.strip();v=v[:-1]+'+00:00' if v.endswith('Z') else v;d=datetime.fromisoformat(v);return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
 except (TypeError,ValueError):return None
def n(v):return str(v or '').strip().casefold()
def readcsv(p):
 with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def flat(o):
 r=set()
 if isinstance(o,dict):
  for k,v in o.items():r.add(str(k).casefold());r.update(flat(v))
 elif isinstance(o,list):
  for v in o:r.update(flat(v))
 elif o is not None:r.add(str(o).strip().casefold())
 return r
@dataclass
class Rec:
 eid:str;captured:Any;system:str;collection:str;rid:str;data:dict;timestamp:Any=None
 @property
 def time(self):return self.timestamp or self.captured
def infer(path,d,ctx=None):
 ctx=ctx or {};low=(path+' '+' '.join(str(v) for v in ctx.values())+' '+' '.join(f'{k} {v}' for k,v in d.items())).casefold();rid=str(d.get('resource_id') or '').casefold();prefix_s=next((val for prefix,val in [('tombstone_','identity_service'),('audit_record_','security_service'),('account_','account_service'),('search_','search_service'),('analytics_','analytics_platform'),('support_','support_platform'),('data_flow_','integration_service'),('backup_','backup_service'),('export_','export_service'),('cache_','cache_service'),('email_delivery_','email_delivery_service'),('marketing_','marketing_platform'),('telemetry_','telemetry_service'),('object_storage_','object_storage')] if rid.startswith(prefix)),'');s=prefix_s or str(d.get('data_store') or d.get('origin_system') or d.get('system_id') or ctx.get('data_store') or ctx.get('origin_system') or '').casefold();c=str(d.get('collection') or d.get('collection_name') or ctx.get('collection') or ctx.get('collection_name') or '').casefold()
 if not s:
  for key,val in [('tombstone','identity_service'),('identity_service','identity_service'),('customer_profiles','account_service'),('customer_accounts','account_service'),('account','account_service'),('audit_record','security_service'),('data_flow','integration_service'),('search','search_service'),('analytics','analytics_platform'),('support','support_platform'),('backup','backup_service'),('export','export_service'),('connector','integration_service'),('marketing','marketing_platform'),('security','security_service'),('email_delivery','email_delivery_service'),('cache','cache_service'),('telemetry','telemetry_service'),('object_storage','object_storage')]:
   if key in low:s=val;break
 if not s:s='unknown_system'
 if not c:
  for key,val in [('deleted_customer_references','deleted_customer_references'),('tombstone','deleted_customer_references'),('customer_profiles','customer_profiles'),('search','customer_search_documents'),('analytics','customer_analytics_reports'),('telemetry','product_telemetry'),('support','support_conversations'),('connector','connector_configurations'),('backup','backup_catalog'),('export','customer_export_jobs'),('cache','profile_cache'),('marketing','marketing_profiles')]:
   if key in low:c=val;break
 if not c:c='unknown_collection'
 return s,c
def jsonrecs(obj,eid,captured,path):
 out=[]
 def walk(x,ctx=None):
  if isinstance(x,dict):
   ctx=dict(ctx or {})
   for k in ('data_store','origin_system','system_id','collection','collection_name','captured_at','snapshot_at'):
    if k in x:ctx[k]=x[k]
   if x.get('resource_id') is not None:
    s,c=infer(path,x,ctx);ts=dt(str(x.get('captured_at') or x.get('snapshot_at') or x.get('observed_at') or ctx.get('captured_at') or ctx.get('snapshot_at') or x.get('updated_at') or ''));out.append(Rec(eid,captured,s,c,str(x['resource_id']),x,ts))
   for key,value in x.items():
     if isinstance(value,(dict,list)):
      child=dict(ctx)
      lowkey=str(key).casefold()
      if lowkey in {'account_service','search_service','analytics_platform','support_platform','integration_service','backup_service','export_service','identity_service','security_service','marketing_platform','cache_service','email_delivery_service','telemetry_service','object_storage'}:child['data_store']=lowkey
      if lowkey in {'profile_lookups','profiles','connectors','restore_entries','exports','index_queries','tickets','audit_records','audit_events','attachments','customer_profiles','customer_search_documents','customer_analytics_reports','support_conversations'}:child['collection']=lowkey
      walk(value,child)
  elif isinstance(x,list):
   for v in x:walk(v,ctx)
 walk(obj);return out
def sqlrecs(path,eid,captured):
 sql=path.read_text(encoding='utf-8',errors='replace')
 if re.search(r'\b(ATTACH|DETACH|VACUUM|LOAD_EXTENSION|CREATE\s+TRIGGER)\b',sql,re.I) or re.search(r'\bPRAGMA\b(?!\s+foreign_keys\s*=\s*(?:ON|OFF)\b)',sql,re.I):return [],'blocked SQL feature'
 sql=re.sub(r'\bPRAGMA\s+foreign_keys\s*=\s*(?:ON|OFF)\s*;?', '', sql, flags=re.I)
 if not re.search(r'\bCREATE\s+TABLE\b',sql,re.I) or not re.search(r'\bINSERT\s+INTO\b',sql,re.I):return [],'unsupported SQL snapshot'
 db=sqlite3.connect(':memory:');out=[]
 try:
  db.executescript(sql)
  for (table,) in db.execute("select name from sqlite_master where type='table'"):
   cols=[r[1] for r in db.execute(f'PRAGMA table_info("{table}")')];lm={c.casefold():c for c in cols};rid=lm.get('resource_id')
   if not rid:continue
   dc=lm.get('record_json') or lm.get('data_json') or lm.get('payload_json');sc=lm.get('origin_system') or lm.get('system_id') or lm.get('data_store');cc=lm.get('collection_name') or lm.get('collection');tc=lm.get('updated_at') or lm.get('captured_at') or lm.get('snapshot_at')
   for row in db.execute(f'SELECT * FROM "{table}"'):
    rawrow=dict(zip(cols,row));raw=rawrow.get(dc) if dc else None
    try:payload=json.loads(raw) if isinstance(raw,str) else {}
    except json.JSONDecodeError:payload={'raw_record':raw}
    if not isinstance(payload,dict):payload={'raw_record':raw}
    # Preserve direct SQL columns as evidence; many snapshots do not wrap rows in JSON.
    for key,value in rawrow.items():
     if key not in {rid,dc,sc,cc,tc} and value is not None:payload.setdefault(key,value)
    payload.setdefault('resource_id',str(rawrow.get(rid)));payload.setdefault('table_name',table)
    if cc and rawrow.get(cc):payload['collection']=rawrow[cc]
    else:payload.setdefault('collection',table)
    if sc and rawrow.get(sc):payload.setdefault('data_store',rawrow[sc])
    s,c=infer(str(path),payload);out.append(Rec(eid,captured,s,c,str(rawrow[rid]),payload,dt(str(rawrow.get(tc) or '')) if tc else None))
 except sqlite3.Error as e:return [],f'SQL parse error: {e}'
 finally:db.close()
 return out,None
class Index:
 def __init__(self):self.records=[];self.text=[];self.warnings=[]
 def at(self,cut):
  # The manifest capture time is a hard upper bound. Embedded timestamps never
  # make evidence from a later-captured file valid for an earlier audit.
  records=[r for r in self.records if r.captured and r.captured<=cut and (not r.timestamp or r.timestamp<=cut)]
  text=[(eid,t,p,b) for eid,t,p,b in self.text if t and t<=cut]
  return records,text
def make_index(dataset):
 idx=Index()
 for m in readcsv(dataset/'evidence_files.csv'):
  eid,rel=m.get('file_id',''),m.get('file_path','');t=dt(m.get('captured_at'));p=dataset/rel
  if not p.is_file():idx.warnings.append(f'{eid}: missing {rel}');continue
  ext=p.suffix.casefold()
  try:
   if ext=='.json':
    body=p.read_text(encoding='utf-8',errors='replace');idx.records.extend(jsonrecs(json.loads(body),eid,t,rel));idx.text.append((eid,t,rel,body))
   elif ext=='.sql':
    rr,err=sqlrecs(p,eid,t);idx.records.extend(rr)
    if err:idx.warnings.append(f'{eid}: {err}')
   elif ext in {'.txt','.log','.csv'}:
    body=p.read_text(encoding='utf-8',errors='replace');idx.text.append((eid,t,rel,body))
    for line in body.splitlines():
     q=line.strip()
     if q.startswith('{') and q.endswith('}'):
      try:idx.records.extend(jsonrecs(json.loads(q),eid,t,rel))
      except json.JSONDecodeError:pass
   elif ext=='.pdf':
    body=''
    try:
     from pypdf import PdfReader
     body='\n'.join(page.extract_text() or '' for page in PdfReader(str(p)).pages)
    except ImportError:
     tool=shutil.which('pdftotext')
     if tool:
      result=subprocess.run([tool,'-layout',str(p),'-'],capture_output=True,text=True,timeout=20,check=False)
      if result.returncode==0:body=result.stdout
    if body.strip():idx.text.append((eid,t,rel,body))
    else:idx.warnings.append(f'{eid}: PDF text extraction unavailable or empty')
   elif ext in {'.png','.jpg','.jpeg','.webp'}:
    try:
     from PIL import Image
     import pytesseract
     body=pytesseract.image_to_string(Image.open(p),config='--psm 6')
     if body.strip():idx.text.append((eid,t,rel,body))
     else:idx.warnings.append(f'{eid}: OCR returned no text')
    except (ImportError, OSError, RuntimeError) as e:idx.warnings.append(f'{eid}: OCR unavailable: {type(e).__name__}')
  except (OSError,json.JSONDecodeError,UnicodeError) as e:idx.warnings.append(f'{eid}: {type(e).__name__}: {e}')
 return idx
NONDEL=[r'\b(access|export|download|copy of my data|correct|rectify|update my (?:name|email|address)|change my email|opt[ -]?out|unsubscribe|stop (?:the )?marketing|marketing preferences|recover my account)\b',r'\b(acceso a mis datos|descargar mis datos|exportar mis datos|corregir mis datos|actualizar mis datos|cancelar la suscripci[oó]n|dejar de recibir publicidad)\b',r'\b(acc[eè]s [àa] mes donn[eé]es|exporter mes donn[eé]es|corriger mes donn[eé]es|modifier mon adresse e-mail)\b']
DEL=[r'\b(delete|deletion|erase|erasure|remove my (?:account|profile|personal data|personal information)|close my account|close this account|account closure|permanent(?:ly)? account deletion|forget me|right to be forgotten|wipe my data|purge my data)\b',r'\b(eliminar|eliminaci[oó]n|borrar|suprimir|supresi[oó]n|cerrar mi cuenta|borrado permanente)\b',r'\b(supprimer|suppression|effacer|cl[oô]turer mon compte|effacement d[eé]finitif)\b',r'\b(l[oö]schen|konto l[oö]schen|konto schlie(?:ß|ss)en|daten entfernen)\b',r'\b(削除|アカウント.*閉鎖|アカウント.*消去|データ.*消去)\b',r'\b(cancellare|eliminare|cancellazione|chiudere il mio account)\b',r'\b(удалить|удаление|закрыть аккаунт)\b',r'\b(?:account|profile|personal data|personal information|this account|it)\b.{0,50}\b(?:closed|deleted|erased|removed|purged|wiped)\b',r'\b(?:would like|want|need|request|asking|please|can you|could you)\b.{0,50}\b(?:close|closed|delete|deleted|erase|erased|remove|removed|purge|purged|wipe|wiped)\b',r'\bdelet(?:e|ed|ing|ion|ions)\b',r'\b(?:delete|deleting|deleted|erase|erased|remove|removed|close|closed|closing|deactivate|deactivated)\b.{0,60}\b(?:my|this|the|an?)?\s*(?:account|profile|personal data|personal information|data)\b',r'\b(?:account|profile|personal data|personal information)\b.{0,60}\b(?:delet(?:e|ed|ing|ion)|eras(?:e|ed|ure)|remov(?:e|ed|al)|clos(?:e|ed|ing))\b']
def authorized(text):
 t=(text or '').casefold()
 # If a request explicitly asks for deletion, accompanying references to an old
 # export/download link or marketing do not turn it into a non-deletion request.
 # Explicit negation takes precedence over the Japanese deletion token.
 if re.search(r'(?:削除しないで|消去しないで|削除を(?:希望しません|望みません)|削除は不要|削除しなくてよい)',t):return False
 if any(term in t for term in ('削除','消去','アカウントを閉鎖','アカウントの削除')):return True
 if any(re.search(p,t,re.I) for p in DEL):return True
 # Requests to verify an already-completed deletion still authorize a deletion audit.
 if re.search(r'\b(?:audit|verify|check|confirm|inspect)\b.{0,100}\b(?:deletion|deleted|erased|removed)\b',t,re.I):return True
 if re.search(r'\b(?:profile|account)\b.{0,80}\b(?:is gone|was removed|fully removed|no longer exists)\b',t,re.I):return True
 return False

def resolve(req,identities,audits,cut):
 email=n(req.get('email'));cur={x.get('user_id',''):x for x in identities if x.get('user_id')}
 current=[x for x in identities if n(x.get('email'))==email]
 found={}
 # Prefer a unique current exact-email match. Historical audit events can reuse
 # an address after reassignment; they must not make an unambiguous current match ambiguous.
 if len(current)>1:return None
 if len(current)==1:
  x=current[0];uid=x.get('user_id','')
  found[uid]={'current':x,'user_id':uid,'emails':set(),'phones':set(),'names':set(),'hashes':set()}
 else:
  for a in audits:
   t=dt(a.get('event_time'))
   if not t or t>cut or (a.get('field_name') or '').casefold()!='email':continue
   if email in {n(a.get('old_value')),n(a.get('new_value'))} and a.get('user_id') in cur:
    uid=a['user_id'];found.setdefault(uid,{'current':cur[uid],'user_id':uid,'emails':set(),'phones':set(),'names':set(),'hashes':set()})
 if len(found)!=1:return None
 x=next(iter(found.values()));c=x['current'];uid=x['user_id'];updated=dt(c.get('updated_at'))
 if c.get('email') and (not updated or updated<=cut):x['emails'].add(n(c['email']))
 if c.get('phone'):x['phones'].add(n(c['phone']))
 if c.get('name'):x['names'].add(n(c['name']))
 if c.get('email_hash'):x['hashes'].add(n(c['email_hash']))
 for a in audits:
  if a.get('user_id')!=uid:continue
  t=dt(a.get('event_time'))
  if not t or t>cut:continue
  f=(a.get('field_name') or '').casefold();target={'email':x['emails'],'phone':x['phones'],'name':x['names'],'full_name':x['names'],'email_hash':x['hashes'],'email_sha256':x['hashes']}.get(f)
  if target is not None:
   if a.get('old_value'):target.add(n(a['old_value']))
   if a.get('new_value'):target.add(n(a['new_value']))
 x['hashes'].update(hashlib.sha256(e.encode()).hexdigest() for e in x['emails']);return x

def matches(r,s):
 needles=set().union(s['emails'],s['phones'],s['names'],s['hashes'],{n(s['user_id'])});needles.discard('');return bool(flat(r.data)&needles)
def has_direct_pii(obj):
 fields={'name','full_name','email','phone','email_hash','requester_email','requester_name','requester_phone','owner_email','customer_email','customer_phone'}
 if isinstance(obj,dict):
  for key,value in obj.items():
   if str(key).casefold() in fields and value is not None and not isinstance(value,(dict,list)) and str(value).strip():return True
   if has_direct_pii(value):return True
 elif isinstance(obj,list):
  return any(has_direct_pii(v) for v in obj)
 return False
def has_linkable_reference(obj):
 fields={'user_id','customer_reference','subject_reference','customer_id','account_id','user_ref','customer_ref','profile_id','subject_id','external_user_id'}
 if isinstance(obj,dict):
  for key,value in obj.items():
   if str(key).casefold() in fields and value is not None and str(value).strip():return True
   if has_linkable_reference(value):return True
 elif isinstance(obj,list):return any(has_linkable_reference(v) for v in obj)
 return False
def is_attachment(r):
 s=(r.system+' '+r.collection+' '+r.rid+' '+' '.join(str(r.data.get(k,'')) for k in ('record_type','category','data_category','file_name','filename','attachment_id','attachment_name','resource_type','artifact_type','file'))).casefold()
 return any(k in s for k in ('attachment','support_file','uploaded_document','identity_document'))
def classify(r,cut=None):
 d=r.data;sy=r.system;co=r.collection;rid=r.rid;s=(sy+' '+co+' '+rid+' '+' '.join(str(d.get(k,'')) for k in ('record_type','category','data_category','file_name','attachment_id'))).casefold()
 exposed=has_direct_pii(d);linked=has_linkable_reference(d)
 if 'tombstone' in s or 'deleted_customer_references' in s:return ('REPORT_EXPOSED_PII','PRESENT') if exposed else ('VERIFY_RECORD_REDACTED','REDACTED')
 if 'connector' in s or 'integration' in sy or rid.startswith('data_flow_'):
  v=d.get('enabled',d.get('is_enabled',d.get('active')))
  if v is True or str(v).casefold() in {'true','1','enabled','active'}:return 'REPORT_ACTIVE_DATA_FLOW','ACTIVE'
  if v is False or str(v).casefold() in {'false','0','disabled','stopped','inactive'}:return 'VERIFY_DATA_FLOW_DISABLED','DISABLED'
 if 'backup' in s or rid.startswith('backup_'):
  v=d.get('restore_allowed',d.get('restore_enabled',d.get('can_restore')))
  if v is True or str(v).casefold() in {'true','1','allowed','active','enabled'}:return 'REPORT_RESTORE_RISK','ACTIVE'
  if v is False or str(v).casefold() in {'false','0','blocked','denied','disabled'}:return 'VERIFY_RESTORE_BLOCKED','BLOCKED'
 if 'legal_hold' in s or 'legal hold' in s:
  active=d.get('active',d.get('is_active',d.get('hold_status',d.get('status'))))
  if active is True or str(active).casefold() in {'true','1','active','open','held','in_force'}:return 'VERIFY_RECORD_PRESENT','PRESENT'
  if active is False or str(active).casefold() in {'false','0','inactive','released','closed','expired'}:return 'REPORT_REMAINING_RECORD','PRESENT'
 if 'security' in sy or 'audit_record' in rid.casefold():
  until=dt(str(d.get('retention_until') or d.get('retain_until') or ''));at=cut or r.time
  if until and at and until<at:return 'REPORT_REMAINING_RECORD','PRESENT'
  return 'VERIFY_RECORD_PRESENT','PRESENT'
 if 'support' in s:
  if is_attachment(r):return 'REPORT_REMAINING_RECORD','PRESENT'
  return ('REPORT_EXPOSED_PII','PRESENT') if exposed else ('VERIFY_RECORD_REDACTED','REDACTED')
 if 'analytics' in s or 'telemetry' in s:
  return ('REPORT_EXPOSED_PII','PRESENT') if exposed or linked else ('VERIFY_RECORD_ANONYMIZED','ANONYMIZED')
 if 'email_delivery' in s:return ('REPORT_EXPOSED_PII','PRESENT') if exposed else ('VERIFY_RECORD_REDACTED','REDACTED')
 if 'search' in s:
  hits=d.get('hits')
  total=hits.get('total') if isinstance(hits,dict) else d.get('total_hits',d.get('total'))
  if str(total).casefold() in {'0','0.0'} or str(d.get('status_code') or '')=='404':return 'VERIFY_RECORD_ABSENT','ABSENT'
  return 'REPORT_REMAINING_RECORD','PRESENT'
 if any(x in s for x in ('export','marketing','cache','secondary_identifier','object_storage')):return 'REPORT_REMAINING_RECORD','PRESENT'
 if 'account' in sy or rid.startswith('account_'):
  st=str(d.get('account_status') or d.get('status') or '').casefold()
  code=str(d.get('status_code') or d.get('http_status') or '').casefold()
  if st in {'deleted','absent','not_found','not found'} or code in {'404','not_found'} or ('profile' in d and d.get('profile') is None):return 'VERIFY_RECORD_ABSENT','ABSENT'
  return 'REPORT_REMAINING_RECORD','PRESENT'
 return 'REPORT_REMAINING_RECORD','PRESENT'
def step(ph,sy,rid,op,state,eid):return {'step_no':0,'phase':ph,'system_id':sy,'resource_id':rid,'operation':op,'state':state,'evidence_id':eid}
def sortsteps(steps):
 unique={(x['phase'],x['system_id'],x['resource_id'],x['operation'],x['state']):x for x in steps};out=list(unique.values());out.sort(key=lambda x:(PHASE[x['phase']],ORDER[x['operation']],x['system_id'],x['resource_id']))
 for i,x in enumerate(out,1):x['step_no']=i
 return out
def plan(op,sy,rid,co,data=None):
 if op=='REPORT_ACTIVE_DATA_FLOW':return 'DISABLE_DATA_FLOW','DISABLED','VERIFY_DATA_FLOW_DISABLED'
 if op=='REPORT_RESTORE_RISK':return 'BLOCK_RESTORE','BLOCKED','VERIFY_RESTORE_BLOCKED'
 if op=='REPORT_REMAINING_RECORD':return 'DELETE_RECORD','ABSENT','VERIFY_RECORD_ABSENT'
 if op=='REPORT_EXPOSED_PII':
  return ('ANONYMIZE_RECORD','ANONYMIZED','VERIFY_RECORD_ANONYMIZED') if any(x in (sy+' '+co+' '+rid).casefold() for x in ('analytics','telemetry')) else ('REDACT_RECORD','REDACTED','VERIFY_RECORD_REDACTED')
def contains_identifier(text,token):
 if not token:return False
 if '@' in token:
  return re.search(r'(?<![A-Za-z0-9._%+-])'+re.escape(token)+r'(?![A-Za-z0-9_%+-]|\.[A-Za-z0-9_-])',text,re.I) is not None
 if token.startswith(('user_','account_','search_','analytics_','support_','data_flow_','backup_','export_','audit_record_','tombstone_')):
  return re.search(r'(?<![A-Za-z0-9_-])'+re.escape(token)+r'(?![A-Za-z0-9_-])',text,re.I) is not None
 if re.fullmatch(r'[a-f0-9]{40,64}',token):return re.search(r'(?<![a-f0-9])'+re.escape(token)+r'(?![a-f0-9])',text,re.I) is not None
 return token in text
def contains_name(text,token):
 if not token:return False
 return re.search(r'(?<![A-Za-z])'+re.escape(token)+r'(?![A-Za-z])',text,re.I) is not None
def evidence_time(r):
 # Snapshot capture time represents the state captured; readback/activity rows have event times.
 return (r.timestamp or r.captured) if r.collection in {'readback','activity_check'} else (r.captured or r.timestamp)
def add_match(matched,r,op,st):
 key=(r.system,r.rid,op,st);old=matched.get(key)
 if old is None or (evidence_time(r) or datetime.min.replace(tzinfo=timezone.utc))>(evidence_time(old[0]) or datetime.min.replace(tzinfo=timezone.utc)):
  matched[key]=(r,op,st)
def audit_case(req,ids,audits,index,activities=None):
 if not authorized(req.get('request_text','')):return 'NOT_APPLICABLE',[]
 cut=dt(req.get('audit_at'))
 if not cut:return 'INCOMPLETE',[]
 subject=resolve(req,ids,audits,cut)
 if not subject:return 'INCOMPLETE',[]
 records,texts=index.at(cut);matched={}
 for r in records:
  if matches(r,subject):
   op,st=classify(r,cut);add_match(matched,r,op,st)
 identifiers={x for x in (subject['emails']|subject['phones']|subject['hashes']|{n(subject['user_id'])}) if x};name_identifiers={x for x in subject['names'] if x}
 resource_pattern=r'\b(?:account|search|analytics|support|data_flow|backup|export|tombstone|audit_record|cache|email_delivery|marketing)_(?:[0-9][a-z0-9_-]*|(?:attachment|message|conversation|query|profile|archive|record)_[0-9][a-z0-9_-]*)\b'
 for eid,t,path,body in texts:
  parsed=[]
  for line in body.splitlines():
   stamp=re.match(r'^\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)',line)
   line_time=dt(stamp.group(1)) if stamp else None
   if line_time and line_time>cut:continue
   parsed.append((line,line_time))
  doc_ids=set(re.findall(resource_pattern,body,re.I));is_doc=path.casefold().endswith(('.pdf','.png','.jpg','.jpeg','.webp'))
  doc_subject=any(contains_identifier(body.casefold(),token) for token in identifiers) or any(contains_name(body.casefold(),name) for name in name_identifiers)
  if is_doc and len(doc_ids)==1 and doc_subject:
   groups={'document':parsed}
  else:
   groups={}
   for ix,(line,line_time) in enumerate(parsed):
    tr=re.search(r'\btrace_id=([^\s]+)',line,re.I)
    group=tr.group(1) if tr else f'line_{ix}'
    groups.setdefault(group,[]).append((line,line_time))
  known={key[1] for key in matched}
  for group in groups.values():
   combined=' '.join(line for line,_ in group).casefold()
   group_ids=set(re.findall(resource_pattern,combined,re.I))
   subject_hit=any(contains_identifier(combined,token) for token in identifiers) or (is_doc and any(contains_name(combined,name) for name in name_identifiers))
   known_in_group=group_ids & known
   # A trace without subject identifiers may update only one previously linked resource.
   if not subject_hit and not (len(group_ids)==1 and len(known_in_group)==1):continue
   for line,line_time in group:
    m=re.search(r"resource[_ ]id\s*[:=]\s*[\"']?([a-z0-9_-]+)",line,re.I)
    if m:rid=m.group(1) if m.lastindex else m.group(0)
    else:
     m=re.search(resource_pattern,line,re.I)
     if not m:continue
     rid=m.group(0)
    if len(group_ids)>1 and subject_hit and rid not in known and not any(contains_identifier(line.casefold(),token) for token in identifiers):continue
    sy=next((v for prefix,v in [('account_','account_service'),('search_','search_service'),('analytics_','analytics_platform'),('support_','support_platform'),('data_flow_','integration_service'),('backup_','backup_service'),('export_','export_service'),('tombstone_','identity_service'),('audit_record_','security_service'),('cache_','cache_service'),('email_delivery_','email_delivery_service')] if rid.startswith(prefix)),'unknown_system')
    if rid.startswith('audit_record_') and (any(q in combined for q in ('rows=1','result=hit','result=found')) or ('security_audit_log' in combined and re.search(r'\bfound\b',combined))):op,st='VERIFY_RECORD_PRESENT','PRESENT'
    elif any(q in combined for q in ('rows=0','http_status=404','status_code=404','result=miss','total_hits=0')) or ('user_profile' in combined and 'not_found' in combined):op,st='VERIFY_RECORD_ABSENT','ABSENT'
    elif rid.startswith('analytics_') and ('contact_lookup' in combined or 'email_opt_in=' in combined):op,st='REPORT_REMAINING_RECORD','PRESENT'
    elif rid.startswith('analytics_') and ('anonymized' in combined or all(q in combined for q in ('email=null','phone=null','email_hash=null'))):op,st='VERIFY_RECORD_ANONYMIZED','ANONYMIZED'
    elif rid.startswith('analytics_') and ('identifiable' in combined or 'analytics_identity_scan' in combined or any(q in combined for q in ('email=','phone=','email_hash='))):op,st='REPORT_EXPOSED_PII','PRESENT'
    elif rid.startswith('support_') and ('support_attachment' in combined and ('found' in combined or 'present' in combined) or 'attachment_pii_scan' in combined):op,st='REPORT_REMAINING_RECORD','PRESENT'
    elif rid.startswith('support_') and ('support_message' in combined and 'redacted' in combined or all(q in combined for q in ('requester_email=null','requester_phone=null'))):op,st='VERIFY_RECORD_REDACTED','REDACTED'
    elif rid.startswith('support_') and ('identifiable' in combined or 'message_pii_scan' in combined or 'requester_email=' in combined and 'requester_email=null' not in combined):op,st='REPORT_EXPOSED_PII','PRESENT'
    elif rid.startswith('backup_') and ('blocked' in combined or 'restore_allowed=false' in combined or 'restore access is blocked' in combined):op,st='VERIFY_RESTORE_BLOCKED','BLOCKED'
    elif rid.startswith('backup_') and ('active' in combined or 'restore_allowed=true' in combined or 'can still be restored' in combined or 'restore access remains allowed' in combined):op,st='REPORT_RESTORE_RISK','ACTIVE'
    elif rid.startswith('data_flow_') and ('disabled' in combined or 'enabled=false' in combined or 'data_flow | disabled' in combined):op,st='VERIFY_DATA_FLOW_DISABLED','DISABLED'
    elif rid.startswith('data_flow_') and ('active' in combined or 'enabled=true' in combined or 'remains enabled' in combined or 'still enabled' in combined):op,st='REPORT_ACTIVE_DATA_FLOW','ACTIVE'
    elif 'search_index_entry' in combined and 'found' in combined:op,st='REPORT_REMAINING_RECORD','PRESENT'
    elif 'user_export' in combined and 'found' in combined:op,st='REPORT_REMAINING_RECORD','PRESENT'
    elif 'support_attachment' in combined and 'found' in combined:op,st='REPORT_REMAINING_RECORD','PRESENT'
    elif any(q in combined for q in ('enabled=false','restore_allowed=false','restore blocked','cannot be restored')):op,st=('VERIFY_DATA_FLOW_DISABLED','DISABLED') if rid.startswith('data_flow_') or 'enabled=false' in combined else ('VERIFY_RESTORE_BLOCKED','BLOCKED')
    elif any(q in combined for q in ('attachment_pii_scan',)):op,st='REPORT_REMAINING_RECORD','PRESENT'
    elif any(q in combined for q in ('message_pii_scan','analytics_identity_scan')):op,st='REPORT_EXPOSED_PII','PRESENT'
    elif any(q in combined for q in ('remains enabled','remains active','still enabled','still active','restore_candidate_evaluated eligible=true','can still be restored','restore access remains allowed')):op,st=('REPORT_ACTIVE_DATA_FLOW','ACTIVE') if rid.startswith('data_flow_') else ('REPORT_RESTORE_RISK','ACTIVE') if rid.startswith('backup_') else ('REPORT_REMAINING_RECORD','PRESENT')
    elif any(q in combined for q in ('result=hit','rows=1','http_status=200','total_hits=1','result=found')):
     op,st=('REPORT_REMAINING_RECORD','PRESENT') if rid.startswith(('account_','search_','export_','marketing_','cache_')) else ('REPORT_EXPOSED_PII','PRESENT')
     if rid.startswith('audit_record_'):op,st='VERIFY_RECORD_PRESENT','PRESENT'
     if rid.startswith('analytics_') and all(q in combined for q in ('email=null','phone=null','email_hash=null')):op,st='VERIFY_RECORD_ANONYMIZED','ANONYMIZED'
     if rid.startswith('data_flow_'):op,st='REPORT_ACTIVE_DATA_FLOW','ACTIVE'
     if rid.startswith('backup_'):op,st='REPORT_RESTORE_RISK','ACTIVE'
    else:continue
    rr=Rec(eid,t,sy,'readback',rid,{'resource_id':rid,'event':combined},line_time or t);add_match(matched,rr,op,st);known.add(rid)
 # Explicit state-check activity is proof; generic operation results are not.
 for a in activities or []:
  at=dt(a.get('event_time'))
  if not at or at>cut:continue
  rid=str(a.get('resource_id') or '');typ=str(a.get('event_type') or '').upper();details=str(a.get('details') or '').casefold()
  if not rid or not (rid in {key[1] for key in matched} or any(contains_identifier(details,token) for token in identifiers)):continue
  if typ=='CHECK_DATA_FLOW':
   if any(x in details for x in ('remains enabled','still enabled','remains active','still active','confirmed enabled')):op,st,sy='REPORT_ACTIVE_DATA_FLOW','ACTIVE','integration_service'
   elif any(x in details for x in ('disabled','not enabled','inactive','stopped')):op,st,sy='VERIFY_DATA_FLOW_DISABLED','DISABLED','integration_service'
   else:continue
  elif typ=='CHECK_RESTORE_ACCESS':
   if any(x in details for x in ('can still be restored','can be restored','restore allowed','remains restorable')):op,st,sy='REPORT_RESTORE_RISK','ACTIVE','backup_service'
   elif any(x in details for x in ('not blocked','is not blocked','not currently blocked','remains possible','remains possible to restore','restore remains possible','restore access is not blocked','restore is still allowed')):op,st,sy='REPORT_RESTORE_RISK','ACTIVE','backup_service'
   elif any(x in details for x in ('blocked','cannot be restored','not restorable','restore denied','restore access is blocked')):op,st,sy='VERIFY_RESTORE_BLOCKED','BLOCKED','backup_service'
   else:continue
  else:continue
  rr=Rec(str(a.get('activity_id') or ''),at,sy,'activity_check',rid,{'resource_id':rid,'details':details},at);add_match(matched,rr,op,st)
 # Use a unique deletion/anonymization action close to the workflow report only to link
 # the resource to this request. The final state still comes from point-in-time evidence.
 report=dt(req.get('reported_at'));requested=dt(req.get('requested_at'))
 if report:
  for event_type,target in (('DELETE_RECORD','account_service'),('ANONYMIZE_RECORD','analytics_platform')):
   if any(sy==target for sy,_,_,_ in matched):continue
   candidates=[]
   for a in activities or []:
    at=dt(a.get('event_time'))
    if not at or at>cut or (requested and at<requested) or str(a.get('event_type') or '').upper()!=event_type:continue
    if str(a.get('target_system') or '').casefold()!=target:continue
    rid=str(a.get('resource_id') or '')
    if (target=='account_service' and not rid.startswith('account_')) or (target=='analytics_platform' and not rid.startswith('analytics_')):continue
    distance=abs((at-report).total_seconds())
    if distance<=600:candidates.append((distance,a))
   if not candidates:continue
   if target=='analytics_platform' and not re.search(r'\b(analytics|telemetry|anonymi[sz]e|anonymous statistics)\b',str(req.get('request_text') or ''),re.I):continue
   # Link by an explicit subject/resource match when available. When the only subject identity is
   # the request email and the event contains no identity fields, a temporal match alone is not proof.
   subject_linked=[]
   for distance,a in candidates:
    identity_text=' '.join(str(a.get(k) or '') for k in ('details','user_id','subject_id','customer_id','email','email_hash','phone'))
    if any(contains_identifier(identity_text,token) for token in identifiers):subject_linked.append((distance,a))
   if len(subject_linked)==1:a=subject_linked[0][1]
   elif len(subject_linked)>1:continue
   else:continue
   rid=str(a.get('resource_id') or '')
   linked=[r for r in records if r.system==target and r.rid==rid]
   if linked:
    newest=max(linked,key=lambda r:evidence_time(r) or datetime.min.replace(tzinfo=timezone.utc))
    op,st=classify(newest,cut);add_match(matched,newest,op,st)
   elif target=='account_service':
    snapshots=[r for r in records if r.system=='account_service' and r.captured and any(k in r.collection.casefold() for k in ('customer_profiles','customer_accounts'))]
    if snapshots:
     latest_capture=max(r.captured for r in snapshots);latest=[r for r in snapshots if r.captured==latest_capture]
     found=[r for r in latest if r.rid==rid]
     if found:
      for r in found:
       op,st=classify(r,cut);add_match(matched,r,op,st)
     else:
      snapshot=sorted(latest,key=lambda r:r.eid)[-1]
      rr=Rec(snapshot.eid,snapshot.captured,'account_service','readback',rid,{'resource_id':rid,'status_code':404},snapshot.captured);add_match(matched,rr,'VERIFY_RECORD_ABSENT','ABSENT')
 # For each resource, use its freshest state; findings win only when evidence times tie.
 latest={}
 for (sy,rid,op,st),(r,_,_) in matched.items():
  when=evidence_time(r) or datetime.min.replace(tzinfo=timezone.utc)
  rank=(when,1 if OP[op][0]=='FINDING' else 0)
  if (sy,rid) not in latest or rank>latest[(sy,rid)][0]:latest[(sy,rid)]=(rank,(r,op,st))
 matched={(sy,r.rid,op,st):(r,op,st) for (sy,_),(rank,(r,op,st)) in latest.items()}
 findings=[];verify=[];rem=[]
 for (sy,rid,op,st),(r,_,_) in matched.items():
  ph=OP[op][0];(findings if ph=='FINDING' else verify).append(step(ph,sy,rid,op,st,r.eid))
 for f in findings:
  r=next((z for z,_,_ in matched.values() if z.system==f['system_id'] and z.rid==f['resource_id']),None);q=plan(f['operation'],f['system_id'],f['resource_id'],r.collection if r else '',r.data if r else {})
  if q:
   rop,rst,vop=q;rem.append(step('REMEDIATION',f['system_id'],f['resource_id'],rop,rst,''));verify.append(step('VERIFICATION',f['system_id'],f['resource_id'],vop,rst,''))
 if findings:return 'INCOMPLETE',sortsteps(findings+rem+verify)
 if verify:return 'COMPLETE',sortsteps(verify)
 return 'INCOMPLETE',[]
def run(dataset,input_path,output):
 requests=readcsv(input_path);ids=readcsv(dataset/'user_identities.csv');audits=readcsv(dataset/'user_audit_log.csv');activities=readcsv(dataset/'system_activity.csv') if (dataset/'system_activity.csv').is_file() else [];ix=make_index(dataset);rows=[]
 for req in requests:
  status,steps=audit_case(req,ids,audits,ix,activities);rows.append({'case_id':req.get('case_id',''),'deletion_status':status,'steps_json':json.dumps(steps,ensure_ascii=False,separators=(',',':'))})
 rows.sort(key=lambda x:x['case_id']);output.parent.mkdir(parents=True,exist_ok=True)
 with output.open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=HEADER,lineterminator='\n');w.writeheader();w.writerows(rows)
 return {'cases':len(rows),'statuses':{s:sum(r['deletion_status']==s for r in rows) for s in ('COMPLETE','INCOMPLETE','NOT_APPLICABLE')},'evidence_records':len(ix.records),'evidence_files':len(readcsv(dataset/'evidence_files.csv')),'warning_count':len(ix.warnings),'warnings':ix.warnings[:12]}
def main():
 root=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dataset',type=Path,default=root/'dataset');p.add_argument('--input',type=Path,default=None);p.add_argument('--output',type=Path,default=root/'output.csv');a=p.parse_args()
 try:r=run(a.dataset,a.input or a.dataset/'deletion_requests.csv',a.output)
 except (OSError,ValueError,csv.Error) as e:print(f'ERROR: {e}',file=sys.stderr);return 2
 print(json.dumps(r,ensure_ascii=False,indent=2));print(f"Wrote {r['cases']} rows to {a.output}");return 0
if __name__=='__main__':raise SystemExit(main())