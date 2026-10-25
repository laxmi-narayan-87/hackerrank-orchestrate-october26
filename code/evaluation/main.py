#!/usr/bin/env python3
"""Structural output validator plus public sample comparison."""
import argparse,csv,json
from collections import Counter
from pathlib import Path
HEADER=['case_id','deletion_status','steps_json'];STATUSES={'COMPLETE','INCOMPLETE','NOT_APPLICABLE'};PHASES={'FINDING':0,'REMEDIATION':1,'VERIFICATION':2}
OPS={'REPORT_REMAINING_RECORD':('FINDING','PRESENT'),'REPORT_EXPOSED_PII':('FINDING','PRESENT'),'REPORT_ACTIVE_DATA_FLOW':('FINDING','ACTIVE'),'REPORT_RESTORE_RISK':('FINDING','ACTIVE'),'DISABLE_DATA_FLOW':('REMEDIATION','DISABLED'),'BLOCK_RESTORE':('REMEDIATION','BLOCKED'),'DELETE_RECORD':('REMEDIATION','ABSENT'),'REDACT_RECORD':('REMEDIATION','REDACTED'),'ANONYMIZE_RECORD':('REMEDIATION','ANONYMIZED'),'VERIFY_RECORD_ABSENT':('VERIFICATION','ABSENT'),'VERIFY_RECORD_PRESENT':('VERIFICATION','PRESENT'),'VERIFY_RECORD_REDACTED':('VERIFICATION','REDACTED'),'VERIFY_RECORD_ANONYMIZED':('VERIFICATION','ANONYMIZED'),'VERIFY_DATA_FLOW_DISABLED':('VERIFICATION','DISABLED'),'VERIFY_RESTORE_BLOCKED':('VERIFICATION','BLOCKED')};KEYS={'step_no','phase','system_id','resource_id','operation','state','evidence_id'}
def read(p):
 with Path(p).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def validate(out,input_path,manifest=None):
 issues=[]
 with Path(out).open(encoding='utf-8-sig',newline='') as f:
  rd=csv.DictReader(f)
  if rd.fieldnames!=HEADER:issues.append(f'header must equal {HEADER}; got {rd.fieldnames}')
  rows=list(rd)
 inp=read(input_path);expected=[x.get('case_id','') for x in inp];ids=[x.get('case_id','') for x in rows]
 if len(rows)!=len(expected):issues.append(f'row count expected {len(expected)} got {len(rows)}')
 if len(ids)!=len(set(ids)):issues.append('duplicate case_id')
 if sorted(ids)!=sorted(expected):issues.append('output case_id set differs from input')
 if ids!=sorted(ids):issues.append('rows are not sorted')
 validids=None
 if manifest and Path(manifest).exists():
  validids={x.get('file_id','') for x in read(manifest)}
  base=Path(manifest).parent
  for filename,key in (('system_activity.csv','activity_id'),('user_audit_log.csv','audit_id')):
   evidence_path=base/filename
   if evidence_path.exists():validids.update(x.get(key,'') for x in read(evidence_path))
 counts=Counter();nt=0
 for row in rows:
  cid=row.get('case_id','');status=row.get('deletion_status','');counts[status]+=1
  if status not in STATUSES:issues.append(f'{cid}: invalid status {status!r}')
  try:steps=json.loads(row.get('steps_json',''))
  except json.JSONDecodeError as e:issues.append(f'{cid}: invalid JSON {e}');continue
  if not isinstance(steps,list):issues.append(f'{cid}: steps_json must be array');continue
  nt+=len(steps)
  if status=='NOT_APPLICABLE' and steps:issues.append(f'{cid}: NOT_APPLICABLE must have []')
  if status=='COMPLETE' and any(not isinstance(s,dict) or s.get('phase')!='VERIFICATION' for s in steps):issues.append(f'{cid}: COMPLETE may contain verification only')
  if [s.get('step_no') for s in steps if isinstance(s,dict)]!=list(range(1,len(steps)+1)):issues.append(f'{cid}: steps not numbered consecutively')
  p=[PHASES.get(s.get('phase'),-1) for s in steps if isinstance(s,dict)]
  if p!=sorted(p):issues.append(f'{cid}: phase order violation')
  for i,s in enumerate(steps,1):
   if not isinstance(s,dict):issues.append(f'{cid}: step {i} not an object');continue
   if set(s)!=KEYS:issues.append(f'{cid}: step {i} keys mismatch')
   op=s.get('operation')
   if op not in OPS:issues.append(f'{cid}: step {i} invalid operation {op!r}')
   elif (s.get('phase'),s.get('state'))!=OPS[op]:issues.append(f'{cid}: step {i} invalid phase/state for {op}')
   eid=s.get('evidence_id','')
   if status=='COMPLETE' and not eid:issues.append(f'{cid}: COMPLETE step {i} missing evidence')
   if status=='INCOMPLETE' and s.get('phase')=='FINDING' and not eid:issues.append(f'{cid}: FINDING step {i} missing evidence')
   if status=='INCOMPLETE' and s.get('phase') in ('REMEDIATION','VERIFICATION') and eid:issues.append(f'{cid}: proposed step {i} must have empty evidence_id')
   if validids is not None and eid and eid not in validids:issues.append(f'{cid}: unknown evidence_id {eid!r}')
 return {'valid':not issues,'input_rows':len(inp),'output_rows':len(rows),'status_counts':dict(counts),'total_steps':nt,'issues':issues}
def compare(out,sample):
 p={x['case_id']:x for x in read(out)};g={x['case_id']:x for x in read(sample)};ids=sorted(set(p)&set(g));sa=ea=qa=0;errors=[]
 def sig(xs):return [(x.get('phase'),x.get('system_id'),x.get('resource_id'),x.get('operation'),x.get('state')) for x in xs]
 for cid in ids:
  a,b=p[cid],g[cid];sa+=a['deletion_status']==b['deletion_status']
  try:ps,gs=json.loads(a['steps_json']),json.loads(b['steps_json'])
  except Exception:ps,gs=[],[{'bad':1}]
  psig,gsig=sig(ps),sig(gs);ea+=ps==gs;qa+=psig==gsig
  if a['deletion_status']!=b['deletion_status'] or ps!=gs:
   pset,gset=set(psig),set(gsig)
   pmap={tuple(sig([s])[0]):s.get('evidence_id','') for s in ps if isinstance(s,dict)}
   gmap={tuple(sig([s])[0]):s.get('evidence_id','') for s in gs if isinstance(s,dict)}
   evidence_mismatches=[{'step_key':list(k),'predicted_evidence_id':pmap[k],'expected_evidence_id':gmap[k]} for k in pmap.keys()&gmap.keys() if pmap[k]!=gmap[k]]
   errors.append({'case_id':cid,'status_match':a['deletion_status']==b['deletion_status'],'predicted_status':a['deletion_status'],'expected_status':b['deletion_status'],'predicted_steps':len(ps),'expected_steps':len(gs),'missing_steps':[s for s in gs if tuple(sig([s])[0]) not in pset][:12],'extra_steps':[s for s in ps if tuple(sig([s])[0]) not in gset][:12],'evidence_mismatches':evidence_mismatches[:12],'order_mismatch':psig!=gsig and pset==gset})
 return {'public_sample_cases_compared':len(ids),'status_accuracy':sa/len(ids) if ids else None,'exact_step_array_accuracy':ea/len(ids) if ids else None,'sequence_accuracy':qa/len(ids) if ids else None,'mismatches':errors,'note':'Public sample calibration only; not hidden-benchmark accuracy.'}
def main():
 root=Path(__file__).resolve().parents[2];p=argparse.ArgumentParser();p.add_argument('--input',type=Path,default=root/'dataset'/'deletion_requests.csv');p.add_argument('--output',type=Path,default=root/'output.csv');p.add_argument('--dataset',type=Path,default=root/'dataset');p.add_argument('--compare-sample',action='store_true');a=p.parse_args();r=validate(a.output,a.input,a.dataset/'evidence_files.csv')
 if a.compare_sample:r['public_sample_comparison']=compare(a.output,a.dataset/'sample_output.csv')
 print(json.dumps(r,ensure_ascii=False,indent=2));return 0 if r['valid'] else 1
if __name__=='__main__':raise SystemExit(main())