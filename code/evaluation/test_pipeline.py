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
if __name__=='__main__':unittest.main(verbosity=2)