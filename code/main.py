#!/usr/bin/env python3
"""Deletion audit baseline, offline and non-destructive."""
from __future__ import annotations
import argparse,csv,hashlib,json,re,sqlite3,sys
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
 ctx=ctx or {};low=(path+' '+' '.join(str(v) for v in ctx.values())+' '+' '.join(f'{k} {v}' for k,v in d.items())).casefold();s=str(d.get('data_store') or d.get('origin_system') or d.get('system_id') or ctx.get('data_store') or ctx.get('origin_system') or '').casefold();c=str(d.get('collection') or d.get('collection_name') or ctx.get('collection') or ctx.get('collection_name') or '').casefold()
 if not s:
  for key,val in [('tombstone','identity_service'),('identity_service','identity_service'),('account','account_service'),('search','search_service'),('analytics','analytics_platform'),('support','support_platform'),('backup','backup_service'),('export','export_service'),('connector','integration_service'),('marketing','marketing_platform'),('security','security_service'),('email_delivery','email_delivery_service'),('cache','cache_service'),('telemetry','telemetry_service'),('object_storage','object_storage')]:
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
   for v in x.values():
    if isinstance(v,(dict,list)):walk(v,ctx)
  elif isinstance(x,list):
   for v in x:walk(v,ctx)
 walk(obj);return out
def sqlrecs(path,eid,captured):
 sql=path.read_text(encoding='utf-8',errors='replace')
 if re.search(r'\b(ATTACH|DETACH|PRAGMA|VACUUM|LOAD_EXTENSION|CREATE\s+TRIGGER)\b',sql,re.I):return [],'blocked SQL feature'
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
    payload.setdefault('resource_id',str(rawrow.get(rid)))
    if sc and rawrow.get(sc):payload.setdefault('data_store',rawrow[sc])
    if cc and rawrow.get(cc):payload.setdefault('collection',rawrow[cc])
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
   elif ext in {'.pdf','.png','.jpg','.jpeg','.webp'}:idx.warnings.append(f'{eid}: OCR not implemented ({ext})')
  except (OSError,json.JSONDecodeError,UnicodeError) as e:idx.warnings.append(f'{eid}: {type(e).__name__}: {e}')
 return idx
NONDEL=[r'\b(access|export|download|copy of my data|correct|rectify|update my (?:name|email|address)|change my email|opt[ -]?out|unsubscribe|stop (?:the )?marketing|marketing preferences|recover my account)\b',r'\b(acceso a mis datos|descargar mis datos|exportar mis datos|corregir mis datos|actualizar mis datos|cancelar la suscripci[oó]n|dejar de recibir publicidad)\b',r'\b(acc[eè]s [àa] mes donn[eé]es|exporter mes donn[eé]es|corriger mes donn[eé]es|modifier mon adresse e-mail)\b']
DEL=[r'\b(delete|deletion|erase|erasure|remove my (?:account|profile|personal data|personal information)|close my account|close this account|account closure|permanent(?:ly)? account deletion|forget me|right to be forgotten|wipe my data|purge my data)\b',r'\b(eliminar|eliminaci[oó]n|borrar|suprimir|supresi[oó]n|cerrar mi cuenta|borrado permanente)\b',r'\b(supprimer|suppression|effacer|cl[oô]turer mon compte|effacement d[eé]finitif)\b',r'\b(l[oö]schen|konto l[oö]schen|konto schlie(?:ß|ss)en|daten entfernen)\b',r'\b(削除|アカウント.*閉鎖|アカウント.*消去|データ.*消去)\b',r'\b(cancellare|eliminare|cancellazione|chiudere il mio account)\b',r'\b(удалить|удаление|закрыть аккаунт)\b',r'\b(?:account|profile|personal data|personal information|this account|it)\b.{0,50}\b(?:closed|deleted|erased|removed|purged|wiped)\b',r'\b(?:would like|want|need|request|asking|please|can you|could you)\b.{0,50}\b(?:close|closed|delete|deleted|erase|erased|remove|removed|purge|purged|wipe|wiped)\b']
def authorized(text):
 t=(text or '').casefold()
 if any(re.search(p,t,re.I) for p in NONDEL):return False
 return any(re.search(p,t,re.I) for p in DEL)
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
def classify(r):
 d=r.data;sy=r.system;co=r.collection;rid=r.rid;s=(sy+' '+co+' '+rid).casefold();exposed=has_direct_pii(d)
 if 'tombstone' in s or 'deleted_customer_references' in s:return ('REPORT_EXPOSED_PII','PRESENT') if exposed else ('VERIFY_RECORD_REDACTED','REDACTED')
 if 'connector' in s or 'integration' in sy or rid.startswith('data_flow_'):
  v=d.get('enabled')
  if v is True or str(v).casefold() in {'true','1','enabled','active'}:return 'REPORT_ACTIVE_DATA_FLOW','ACTIVE'
  if v is False or str(v).casefold() in {'false','0','disabled','stopped'}:return 'VERIFY_DATA_FLOW_DISABLED','DISABLED'
 if 'backup' in s or rid.startswith('backup_'):
  v=d.get('restore_allowed')
  if v is True or str(v).casefold() in {'true','1','allowed','active'}:return 'REPORT_RESTORE_RISK','ACTIVE'
  if v is False or str(v).casefold() in {'false','0','blocked','denied'}:return 'VERIFY_RESTORE_BLOCKED','BLOCKED'
 if 'security' in sy or 'audit_record' in rid.casefold():return 'VERIFY_RECORD_PRESENT','PRESENT'
 if 'support' in s:return ('REPORT_EXPOSED_PII','PRESENT') if exposed else ('VERIFY_RECORD_REDACTED','REDACTED')
 if 'analytics' in s or 'telemetry' in s:return ('REPORT_EXPOSED_PII','PRESENT') if exposed else ('VERIFY_RECORD_ANONYMIZED','ANONYMIZED')
 if 'email_delivery' in s:return ('REPORT_EXPOSED_PII','PRESENT') if exposed else ('VERIFY_RECORD_REDACTED','REDACTED')
 if any(x in s for x in ('export','marketing','search','cache')):return 'REPORT_REMAINING_RECORD','PRESENT'
 if 'account' in sy or rid.startswith('account_'):
  st=str(d.get('account_status') or d.get('status') or '').casefold()
  if st in {'deleted','absent','not_found','not found'}:return 'VERIFY_RECORD_ABSENT','ABSENT'
  return 'REPORT_REMAINING_RECORD','PRESENT'
 return 'REPORT_REMAINING_RECORD','PRESENT'
def step(ph,sy,rid,op,state,eid):return {'step_no':0,'phase':ph,'system_id':sy,'resource_id':rid,'operation':op,'state':state,'evidence_id':eid}
def sortsteps(steps):
 unique={(x['phase'],x['system_id'],x['resource_id'],x['operation'],x['state']):x for x in steps};out=list(unique.values());out.sort(key=lambda x:(PHASE[x['phase']],ORDER[x['operation']],x['system_id'],x['resource_id']))
 for i,x in enumerate(out,1):x['step_no']=i
 return out
def plan(op,sy,rid,co):
 if op=='REPORT_ACTIVE_DATA_FLOW':return 'DISABLE_DATA_FLOW','DISABLED','VERIFY_DATA_FLOW_DISABLED'
 if op=='REPORT_RESTORE_RISK':return 'BLOCK_RESTORE','BLOCKED','VERIFY_RESTORE_BLOCKED'
 if op=='REPORT_REMAINING_RECORD':return 'DELETE_RECORD','ABSENT','VERIFY_RECORD_ABSENT'
 if op=='REPORT_EXPOSED_PII':return ('ANONYMIZE_RECORD','ANONYMIZED','VERIFY_RECORD_ANONYMIZED') if 'analytics' in (sy+' '+co+' '+rid).casefold() else ('REDACT_RECORD','REDACTED','VERIFY_RECORD_REDACTED')
def audit_case(req,ids,audits,index):
 if not authorized(req.get('request_text','')):return 'NOT_APPLICABLE',[]
 cut=dt(req.get('audit_at'))
 if not cut:return 'INCOMPLETE',[]
 subject=resolve(req,ids,audits,cut)
 if not subject:return 'INCOMPLETE',[]
 records,texts=index.at(cut);matched={}
 for r in records:
  if matches(r,subject):
   op,st=classify(r);matched.setdefault((r.system,r.rid,op,st),(r,op,st))
 for eid,t,path,body in texts:
  for line in body.splitlines():
   low=line.casefold();emails=[e for e in subject['emails'] if e and e in low]
   if not emails:continue
   m=re.search(r'resource_id[=\"\']+([a-z0-9_-]+)',line,re.I)
   if not m:continue
   rid=m.group(1);sy=next((v for prefix,v in [('account_','account_service'),('search_','search_service'),('analytics_','analytics_platform'),('support_','support_platform'),('data_flow_','integration_service'),('backup_','backup_service'),('export_','export_service'),('tombstone_','identity_service')] if rid.startswith(prefix)),'unknown_system')
   if any(q in low for q in ('rows=0','http_status=404','status_code=404','result=miss','total_hits=0')):op,st='VERIFY_RECORD_ABSENT','ABSENT'
   elif 'enabled=false' in low:op,st='VERIFY_DATA_FLOW_DISABLED','DISABLED'
   elif 'restore_allowed=false' in low:op,st='VERIFY_RESTORE_BLOCKED','BLOCKED'
   elif any(q in low for q in ('result=hit','rows=1','http_status=200','total_hits=1')):
    op,st=('REPORT_REMAINING_RECORD','PRESENT') if rid.startswith(('account_','search_','export_','marketing_','cache_')) else ('REPORT_EXPOSED_PII','PRESENT')
    if rid.startswith('data_flow_'):op,st='REPORT_ACTIVE_DATA_FLOW','ACTIVE'
    if rid.startswith('backup_'):op,st='REPORT_RESTORE_RISK','ACTIVE'
   else:continue
   rr=Rec(eid,t,sy,'readback',rid,{'resource_id':rid,'matched_email':emails[0]},t);matched.setdefault((sy,rid,op,st),(rr,op,st))
 findings=[];verify=[];rem=[]
 for (sy,rid,op,st),(r,_,_) in matched.items():
  ph=OP[op][0];(findings if ph=='FINDING' else verify).append(step(ph,sy,rid,op,st,r.eid))
 for f in findings:
  r=next((z for z,_,_ in matched.values() if z.system==f['system_id'] and z.rid==f['resource_id']),None);q=plan(f['operation'],f['system_id'],f['resource_id'],r.collection if r else '')
  if q:
   rop,rst,vop=q;rem.append(step('REMEDIATION',f['system_id'],f['resource_id'],rop,rst,''));verify.append(step('VERIFICATION',f['system_id'],f['resource_id'],vop,rst,''))
 if findings:return 'INCOMPLETE',sortsteps(findings+rem+verify)
 if verify:return 'COMPLETE',sortsteps(verify)
 return 'INCOMPLETE',[]
def run(dataset,input_path,output):
 requests=readcsv(input_path);ids=readcsv(dataset/'user_identities.csv');audits=readcsv(dataset/'user_audit_log.csv');ix=make_index(dataset);rows=[]
 for req in requests:
  status,steps=audit_case(req,ids,audits,ix);rows.append({'case_id':req.get('case_id',''),'deletion_status':status,'steps_json':json.dumps(steps,ensure_ascii=False,separators=(',',':'))})
 rows.sort(key=lambda x:x['case_id']);output.parent.mkdir(parents=True,exist_ok=True)
 with output.open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=HEADER,lineterminator='\n');w.writeheader();w.writerows(rows)
 return {'cases':len(rows),'statuses':{s:sum(r['deletion_status']==s for r in rows) for s in ('COMPLETE','INCOMPLETE','NOT_APPLICABLE')},'evidence_records':len(ix.records),'evidence_files':len(readcsv(dataset/'evidence_files.csv')),'warning_count':len(ix.warnings),'warnings':ix.warnings[:12]}
def main():
 root=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dataset',type=Path,default=root/'dataset');p.add_argument('--input',type=Path,default=None);p.add_argument('--output',type=Path,default=root/'output.csv');a=p.parse_args()
 try:r=run(a.dataset,a.input or a.dataset/'deletion_requests.csv',a.output)
 except (OSError,ValueError,csv.Error) as e:print(f'ERROR: {e}',file=sys.stderr);return 2
 print(json.dumps(r,ensure_ascii=False,indent=2));print(f"Wrote {r['cases']} rows to {a.output}");return 0
if __name__=='__main__':raise SystemExit(main())