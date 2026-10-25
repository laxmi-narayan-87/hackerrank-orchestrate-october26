import importlib.util,json,sys,tempfile,unittest,csv
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
main=load('audit_main',ROOT/'code'/'main.py');ev=load('audit_eval',ROOT/'code'/'evaluation'/'main.py')
class Intent(unittest.TestCase):
 def test_delete(self):self.assertTrue(main.authorized('Please permanently delete my account and personal data.'))
 def test_export(self):self.assertFalse(main.authorized('Please export a copy of my data.'))
 def test_correction(self):self.assertFalse(main.authorized('Please correct my email address.'))
 def test_french_delete(self):self.assertTrue(main.authorized('Je demande la suppression définitive du compte associé à cette adresse.'))
class Evidence(unittest.TestCase):
 def test_cutoff(self):
  ix=main.Index();ix.text=[('e1',main.dt('2026-09-01T00:00:00Z'),'a.log','old'),('e2',main.dt('2026-09-03T00:00:00Z'),'b.log','future')];self.assertEqual([x[0] for x in ix.at(main.dt('2026-09-02T00:00:00Z'))[1]],['e1'])
 def test_no_fuzzy_join(self):
  r=main.Rec('e1',main.dt('2026-09-01T00:00:00Z'),'search_service','search','search_1',{'email':'somebody.jr@gmail.com'});s={'user_id':'user_1','emails':{'somebody@gmail.com'},'phones':set(),'names':set(),'hashes':set()};self.assertFalse(main.matches(r,s))
 def test_op_state(self):self.assertEqual(main.OP['BLOCK_RESTORE'],('REMEDIATION','BLOCKED'))
 def test_step_dedupe(self):
  a=main.step('FINDING','search_service','search_1','REPORT_REMAINING_RECORD','PRESENT','evidence_1');self.assertEqual(len(main.sortsteps([a,dict(a)])),1);self.assertEqual(main.sortsteps([a])[0]['step_no'],1)
 def test_tombstone_redact(self):
  r=main.Rec('e51',main.dt('2026-09-15T12:00:00Z'),'identity_service','deleted_customer_references','tombstone_9178',{'name':'Example','email':'person@example.com','phone':'+15550100','email_hash':'abc'});self.assertEqual(main.classify(r),('REPORT_EXPOSED_PII','PRESENT'))
 def test_enabled_flow(self):
  r=main.Rec('e92',main.dt('2026-09-15T11:44:55Z'),'integration_service','connector_configurations','data_flow_123',{'enabled':True});self.assertEqual(main.classify(r),('REPORT_ACTIVE_DATA_FLOW','ACTIVE'))
 def test_restore(self):
  r=main.Rec('e92',main.dt('2026-09-15T11:44:55Z'),'backup_service','backup_catalog','backup_123',{'restore_allowed':True});self.assertEqual(main.classify(r),('REPORT_RESTORE_RISK','ACTIVE'))
 def test_null_identifiers_are_not_exposed_pii(self):
  r=main.Rec('e51',main.dt('2026-09-15T12:00:00Z'),'identity_service','deleted_customer_references','tombstone_9178',{'name':None,'email':None,'phone':None,'email_hash':None,'subject_reference':'user_542'});self.assertEqual(main.classify(r),('VERIFY_RECORD_REDACTED','REDACTED'))
 def test_embedded_timestamp_does_not_override_late_capture(self):
  ix=main.Index();ix.records=[main.Rec('e_future',main.dt('2026-09-03T00:00:00Z'),'search_service','customer_search_documents','search_1',{'email':'x@example.com'},main.dt('2026-09-01T00:00:00Z'))];records,_=ix.at(main.dt('2026-09-02T00:00:00Z'));self.assertEqual(records,[])
class Validator(unittest.TestCase):
 def inp(self,d):
  p=d/'in.csv';p.write_text('case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\ncase_01,a@example.com,2026-01-01T00:00:00Z,NOT_STARTED,2026-01-01T00:00:00Z,2026-01-02T00:00:00Z,delete my account\n',encoding='utf8');return p
 def out(self,p,status,steps):
  with p.open('w',newline='',encoding='utf8') as f:w=csv.DictWriter(f,fieldnames=['case_id','deletion_status','steps_json']);w.writeheader();w.writerow({'case_id':'case_01','deletion_status':status,'steps_json':json.dumps(steps)})
 def test_bad_op_state(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);i=self.inp(d);o=d/'out.csv';self.out(o,'INCOMPLETE',[{'step_no':1,'phase':'FINDING','system_id':'search_service','resource_id':'search_1','operation':'DELETE_RECORD','state':'ABSENT','evidence_id':'evidence_1'}]);r=ev.validate(o,i);self.assertFalse(r['valid']);self.assertTrue(any('phase/state' in x for x in r['issues']))
 def test_notapplicable_requires_empty(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);i=self.inp(d);o=d/'out.csv';self.out(o,'NOT_APPLICABLE',[{'step_no':1,'phase':'VERIFICATION','system_id':'account_service','resource_id':'account_1','operation':'VERIFY_RECORD_ABSENT','state':'ABSENT','evidence_id':'evidence_1'}]);r=ev.validate(o,i);self.assertFalse(r['valid']);self.assertTrue(any('NOT_APPLICABLE' in x for x in r['issues']))

class PolicyRegression(unittest.TestCase):
 def rec(self,system,collection,rid,data):
  return main.Rec('evidence_test',main.dt('2026-09-01T00:00:00Z'),system,collection,rid,data)
 def test_sql_snapshot_preserves_direct_identity_columns(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'snapshot.sql'
   p.write_text("CREATE TABLE customer_profiles_primary (resource_id TEXT, user_id TEXT, email TEXT, phone TEXT, account_status TEXT, updated_at TEXT); INSERT INTO customer_profiles_primary VALUES ('account_1','user_1','x@example.com','+15550000000','ACTIVE','2026-09-01T00:00:00Z');",encoding='utf8')
   records,error=main.sqlrecs(p,'evidence_test',main.dt('2026-09-02T00:00:00Z'))
   self.assertIsNone(error);self.assertEqual(len(records),1)
   self.assertEqual(records[0].data.get('email'),'x@example.com')
   self.assertEqual(records[0].system,'account_service')
   self.assertEqual(records[0].collection,'customer_profiles_primary')
 def test_attributable_analytics_is_not_mistaken_for_anonymized(self):
  r=self.rec('analytics_platform','customer_analytics_reports','analytics_1',{'user_id':'user_1','email':None,'phone':None,'email_hash':None})
  self.assertEqual(main.classify(r),('REPORT_EXPOSED_PII','PRESENT'))
 def test_support_attachment_requires_deletion(self):
  r=self.rec('support_platform','support_attachments','support_attachment_1',{'file_name':'identity_document.pdf','email':'x@example.com'})
  self.assertEqual(main.classify(r),('REPORT_REMAINING_RECORD','PRESENT'))
  self.assertEqual(main.plan('REPORT_REMAINING_RECORD',r.system,r.rid,r.collection,r.data),('DELETE_RECORD','ABSENT','VERIFY_RECORD_ABSENT'))
 def test_shared_support_context_without_direct_pii_is_redacted(self):
  r=self.rec('support_platform','support_conversations','support_1',{'customer_reference':'user_1','requester_email':None,'message_excerpt':'shared order context'})
  self.assertEqual(main.classify(r),('VERIFY_RECORD_REDACTED','REDACTED'))
 def test_expired_security_retention_is_not_treated_as_required_retention(self):
  r=self.rec('security_service','security_audit_events','audit_record_1',{'subject_reference':'user_1','retention_until':'2026-08-31T00:00:00Z'})
  self.assertEqual(main.classify(r,main.dt('2026-09-01T00:00:00Z')),('REPORT_REMAINING_RECORD','PRESENT'))
 def test_explicit_restore_check_is_evidence_but_generic_success_is_not(self):
  req={'email':'x@example.com','request_text':'Please delete my account','audit_at':'2026-09-02T00:00:00Z'}
  ids=[{'user_id':'user_1','name':'X User','email':'x@example.com','phone':'+15550000000','email_hash':'','updated_at':'2026-08-01T00:00:00Z'}]
  activities=[
   {'activity_id':'activity_check_1','event_time':'2026-09-01T00:00:00Z','event_type':'CHECK_RESTORE_ACCESS','resource_id':'backup_1','reported_result':'SUCCESS','details':'Restore-access check confirmed archive backup_1 can still be restored for x@example.com.'},
   {'activity_id':'activity_claim_1','event_time':'2026-09-01T00:01:00Z','event_type':'DELETE_RECORD','resource_id':'account_1','reported_result':'SUCCESS','details':'Deletion worker submitted account_1 for x@example.com.'}
  ]
  ix=main.Index();ix.records=[main.Rec('evidence_backup',main.dt('2026-08-30T00:00:00Z'),'backup_service','backup_catalog','backup_1',{'email':'x@example.com','restore_allowed':False},main.dt('2026-08-30T00:00:00Z'))];status,steps=main.audit_case(req,ids,[],ix,activities)
  self.assertEqual(status,'INCOMPLETE')
  self.assertEqual([(s['operation'],s['evidence_id']) for s in steps if s['phase']=='FINDING'],[('REPORT_RESTORE_RISK','activity_check_1')])
  self.assertFalse(any(s['evidence_id']=='activity_claim_1' for s in steps))
 def test_validator_accepts_activity_ids_as_evidence(self):
  with tempfile.TemporaryDirectory() as td:
   d=Path(td);inp=d/'in.csv';out=d/'out.csv';manifest=d/'evidence_files.csv'
   inp.write_text('case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\ncase_01,a@example.com,2026-01-01T00:00:00Z,NOT_STARTED,2026-01-01T00:00:00Z,2026-01-02T00:00:00Z,delete my account\n',encoding='utf8')
   manifest.write_text('file_id,file_path,origin,captured_at\n',encoding='utf8')
   (d/'system_activity.csv').write_text('activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details\nactivity_1,2026-09-01T00:00:00Z,CHECK_RESTORE_ACCESS,worker,backup_service,backup_1,SUCCESS,restore check\n',encoding='utf8')
   (d/'user_audit_log.csv').write_text('audit_id,user_id,event_time,field_name,old_value,new_value\n',encoding='utf8')
   steps=[{'step_no':1,'phase':'FINDING','system_id':'backup_service','resource_id':'backup_1','operation':'REPORT_RESTORE_RISK','state':'ACTIVE','evidence_id':'activity_1'},{'step_no':2,'phase':'REMEDIATION','system_id':'backup_service','resource_id':'backup_1','operation':'BLOCK_RESTORE','state':'BLOCKED','evidence_id':''},{'step_no':3,'phase':'VERIFICATION','system_id':'backup_service','resource_id':'backup_1','operation':'VERIFY_RESTORE_BLOCKED','state':'BLOCKED','evidence_id':''}]
   with out.open('w',newline='',encoding='utf8') as handle:
    writer=csv.DictWriter(handle,fieldnames=['case_id','deletion_status','steps_json']);writer.writeheader();writer.writerow({'case_id':'case_01','deletion_status':'INCOMPLETE','steps_json':json.dumps(steps)})
   result=ev.validate(out,inp,manifest)
   self.assertTrue(result['valid'],result['issues'])


 def test_japanese_deletion_intent_and_deletion_audit_language(self):
  self.assertTrue(main.authorized('このメールアドレスに関連するアカウントの完全な削除を依頼します。'))
  self.assertTrue(main.authorized('Please confirm that the profile is gone and audit the deletion.'))
 def test_trace_id_correlates_identifier_and_resource(self):
  req={'email':'x@example.com','request_text':'Please delete my account','audit_at':'2026-09-02T00:00:00Z'}
  ids=[{'user_id':'user_1','name':'X User','email':'x@example.com','phone':'','email_hash':'','updated_at':'2026-08-01T00:00:00Z'}]
  ix=main.Index();ix.text=[('evidence_log',main.dt('2026-09-01T00:00:00Z'),'lookup.log','2026-09-01T00:00:00Z trace_id=abc event=profile_lookup_started lookup_key="x@example.com"\\n2026-09-01T00:00:01Z trace_id=abc resource_id=account_1 event=profile_lookup_completed rows=0 http_status=404')]
  status,steps=main.audit_case(req,ids,[],ix,[])
  self.assertEqual(status,'COMPLETE')
  self.assertEqual([(x['resource_id'],x['operation']) for x in steps],[('account_1','VERIFY_RECORD_ABSENT')])
 def test_similar_email_in_text_does_not_match(self):
  req={'email':'x@example.com','request_text':'Please delete my account','audit_at':'2026-09-02T00:00:00Z'}
  ids=[{'user_id':'user_1','name':'X User','email':'x@example.com','phone':'','email_hash':'','updated_at':'2026-08-01T00:00:00Z'}]
  ix=main.Index();ix.text=[('evidence_log',main.dt('2026-09-01T00:00:00Z'),'lookup.log','2026-09-01T00:00:00Z trace_id=abc lookup_key="x@example.com.evil"\\n2026-09-01T00:00:01Z trace_id=abc resource_id=account_2 rows=0 http_status=404')]
  status,steps=main.audit_case(req,ids,[],ix,[])
  self.assertEqual(status,'INCOMPLETE')
  self.assertEqual(steps,[])
 def test_latest_readback_overrides_stale_profile(self):
  req={'email':'x@example.com','request_text':'Please delete my account','audit_at':'2026-09-03T00:00:00Z'}
  ids=[{'user_id':'user_1','name':'X User','email':'x@example.com','phone':'','email_hash':'','updated_at':'2026-08-01T00:00:00Z'}]
  ix=main.Index()
  ix.records=[
   main.Rec('old_snapshot',main.dt('2026-09-01T00:00:00Z'),'account_service','customer_profiles','account_1',{'resource_id':'account_1','user_id':'user_1','email':'x@example.com','account_status':'ACTIVE'}),
   main.Rec('latest_readback',main.dt('2026-09-02T00:00:00Z'),'account_service','readback','account_1',{'resource_id':'account_1','email':'x@example.com','status_code':404},main.dt('2026-09-02T00:00:00Z'))
  ]
  status,steps=main.audit_case(req,ids,[],ix,[])
  self.assertEqual(status,'COMPLETE')
  self.assertEqual([(x['operation'],x['evidence_id']) for x in steps],[('VERIFY_RECORD_ABSENT','latest_readback')])
 def test_nested_service_export_infers_system_from_parent_key(self):
  obj={'service_exports':{'account_service':{'profile_lookups':[{'resource_id':'account_1','status_code':404,'profile':None}]}}}
  recs=main.jsonrecs(obj,'e1',main.dt('2026-09-01T00:00:00Z'),'service_resource_export.json')
  self.assertEqual(len(recs),1)
  self.assertEqual(recs[0].system,'account_service')
  self.assertEqual(main.classify(recs[0]),('VERIFY_RECORD_ABSENT','ABSENT'))


 def test_sql_snapshot_allows_safe_foreign_keys_pragma(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'snapshot.sql'
   p.write_text("PRAGMA foreign_keys=ON; BEGIN TRANSACTION; CREATE TABLE customer_profiles_primary (resource_id TEXT, user_id TEXT, email TEXT, account_status TEXT, updated_at TEXT); INSERT INTO customer_profiles_primary VALUES ('account_5','user_5','y@example.com','ACTIVE','2026-09-01T00:00:00Z'); COMMIT;",encoding='utf8')
   records,error=main.sqlrecs(p,'e1',main.dt('2026-09-02T00:00:00Z'))
   self.assertIsNone(error);self.assertEqual(len(records),1);self.assertEqual(records[0].data.get('email'),'y@example.com')
 def test_handover_text_statuses_are_classified_by_category(self):
  req={'email':'x@example.com','request_text':'Please delete my account','audit_at':'2026-09-02T00:00:00Z'}
  ids=[{'user_id':'user_1','name':'X User','email':'x@example.com','phone':'','email_hash':'','updated_at':'2026-08-01T00:00:00Z'}]
  body='2026-09-01T00:00:00Z | account_service | account_1 | USER_PROFILE | NOT_FOUND | x@example.com\n2026-09-01T00:00:00Z | security_service | audit_record_1 | SECURITY_AUDIT_LOG | FOUND | user_1'
  ix=main.Index();ix.text=[('evidence_handover',main.dt('2026-09-01T00:00:00Z'),'handover.txt',body)]
  status,steps=main.audit_case(req,ids,[],ix,[])
  self.assertEqual(status,'COMPLETE')
  self.assertEqual({x['operation'] for x in steps},{'VERIFY_RECORD_ABSENT','VERIFY_RECORD_PRESENT'})
 def test_unique_report_time_delete_links_resource_to_snapshot_absence(self):
  req={'email':'x@example.com','requested_at':'2026-09-01T08:00:00Z','reported_at':'2026-09-02T10:00:00Z','request_text':'Please delete my account','audit_at':'2026-09-03T00:00:00Z'}
  ids=[{'user_id':'user_1','name':'X User','email':'x@example.com','phone':'','email_hash':'','updated_at':'2026-08-01T00:00:00Z'}]
  ix=main.Index();ix.records=[main.Rec('snapshot_evidence',main.dt('2026-09-02T09:00:00Z'),'account_service','customer_profiles_primary','account_5',{'resource_id':'account_5','user_id':'user_5','email':'y@example.com','account_status':'ACTIVE'})]
  activities=[{'activity_id':'activity_delete','event_time':'2026-09-02T09:59:00Z','event_type':'DELETE_RECORD','source_system':'deletion_worker','target_system':'account_service','resource_id':'account_1','reported_result':'SUCCESS','details':'Deletion worker submitted account_1 for user_1 / x@example.com.'}]
  status,steps=main.audit_case(req,ids,[],ix,activities)
  self.assertEqual(status,'COMPLETE')
  self.assertEqual([(x['resource_id'],x['operation'],x['evidence_id']) for x in steps],[('account_1','VERIFY_RECORD_ABSENT','snapshot_evidence')])
 def test_near_report_anonymize_links_only_the_anonymized_record_state(self):
  req={'email':'x@example.com','requested_at':'2026-09-01T08:00:00Z','reported_at':'2026-09-02T10:00:00Z','request_text':'I am deleting my account; anonymous analytics may remain.','audit_at':'2026-09-03T00:00:00Z'}
  ids=[{'user_id':'user_1','name':'X User','email':'x@example.com','phone':'','email_hash':'','updated_at':'2026-08-01T00:00:00Z'}]
  ix=main.Index();ix.records=[main.Rec('analytics_snapshot',main.dt('2026-09-02T09:00:00Z'),'analytics_platform','customer_analytics_reports','analytics_1',{'resource_id':'analytics_1','user_id':None,'email':None,'phone':None,'email_hash':None})]
  activities=[{'activity_id':'activity_anonymize','event_time':'2026-09-02T09:55:00Z','event_type':'ANONYMIZE_RECORD','source_system':'deletion_worker','target_system':'analytics_platform','resource_id':'analytics_1','reported_result':'SUCCESS','details':'Anonymization operation reported complete for user_1 / x@example.com.'}]
  status,steps=main.audit_case(req,ids,[],ix,activities)
  self.assertEqual(status,'COMPLETE')
  self.assertEqual([(x['operation'],x['evidence_id']) for x in steps],[('VERIFY_RECORD_ANONYMIZED','analytics_snapshot')])

 def test_negated_japanese_deletion_request_is_not_applicable(self):
  for phrase in ('削除しないでください','このデータの削除は希望していません'):
   req={'email':'x@example.com','request_text':phrase,'audit_at':'2026-09-02T00:00:00Z'}
   status,steps=main.audit_case(req,[],[],main.Index(),[])
   self.assertEqual(status,'NOT_APPLICABLE',phrase)
   self.assertEqual(steps,[],phrase)


if __name__=='__main__':unittest.main(verbosity=2)
