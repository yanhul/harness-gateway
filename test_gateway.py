import hashlib, hmac, json, os, tempfile, time, unittest
from gateway import Ledger, verify_github_signature, normalize_workflow_run

class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.NamedTemporaryFile(delete=False); self.tmp.close()
        self.l=Ledger(self.tmp.name); os.environ['AUTHORIZED_PHONE']='+84123456789'
    def tearDown(self): os.unlink(self.tmp.name)
    def event(self):
        return {'repo':'yanhul/AIOS','workflow':'CI','run_id':123,'head_sha':'a'*40,
                'conclusion':'failure','run_url':'https://github.com/yanhul/AIOS/actions/runs/123',
                'failure':'test_failure','diagnosis':'x','proposed_action':'patch implementation',
                'governance_digest':'f'*64}
    def authorize(self):
        t,nonce=self.l.create(self.event())
        self.l.command('+84123456789',f'SUA {t["ticket"]} {nonce}',True,'f'*64)
        return t
    def test_signature(self):
        b=b'{}'; s=hmac.new(b'secret',b,hashlib.sha256).hexdigest()
        self.assertTrue(verify_github_signature(b,'sha256='+s,'secret'))
        self.assertFalse(verify_github_signature(b,'sha256='+('0'*64),'secret'))
    def test_normalize_real_workflow_payload(self):
        p={'repository':{'full_name':'yanhul/AIOS'},'workflow_run':{
            'id':123,'name':'CI','head_sha':'a'*40,'conclusion':'failure',
            'html_url':'https://github.com/yanhul/AIOS/actions/runs/123'},'governance_digest':'f'*64}
        self.assertEqual(normalize_workflow_run(p)['repo'],'yanhul/AIOS')
    def test_normalize_rejects_unknown_repo(self):
        p={'repository':{'full_name':'evil/repo'},'workflow_run':{
            'id':123,'name':'CI','head_sha':'a'*40,'conclusion':'failure',
            'html_url':'https://github.com/evil/repo/actions/runs/123'},'governance_digest':'f'*64}
        with self.assertRaises(ValueError): normalize_workflow_run(p)
    def test_normalize_rejects_missing_governance(self):
        p={'repository':{'full_name':'yanhul/AIOS'},'workflow_run':{
            'id':123,'name':'CI','head_sha':'a'*40,'conclusion':'failure',
            'html_url':'https://github.com/yanhul/AIOS/actions/runs/123'}}
        with self.assertRaises(ValueError): normalize_workflow_run(p)
    def test_duplicate_event_idempotent(self):
        a=self.l.create(self.event()); b=self.l.create(self.event())
        self.assertEqual(a[0]['ticket'],b[0]['ticket']); self.assertFalse(b[1])
    def test_wrong_sender_rejected(self):
        t,nonce=self.l.create(self.event())
        with self.assertRaises(PermissionError): self.l.command('+84000000000',f'SUA {t["ticket"]} {nonce}',True,'f'*64)
    def test_wrong_nonce_rejected(self):
        t,nonce=self.l.create(self.event())
        with self.assertRaises(PermissionError): self.l.command('+84123456789',f'SUA {t["ticket"]} bad',True,'f'*64)
    def test_nonce_replay_rejected(self):
        t,nonce=self.l.create(self.event()); self.l.command('+84123456789',f'SUA {t["ticket"]} {nonce}',True,'f'*64)
        with self.assertRaises(PermissionError): self.l.command('+84123456789',f'SUA {t["ticket"]} {nonce}',True,'f'*64)
    def test_governance_mismatch_blocks(self):
        t,nonce=self.l.create(self.event())
        with self.assertRaises(PermissionError): self.l.command('+84123456789',f'SUA {t["ticket"]} {nonce}',True,'e'*64)
        self.assertEqual(self.l.get(t['ticket'])['status'],'BLOCKED')
    def test_sha_binding(self):
        t=self.authorize()
        with self.assertRaises(PermissionError): self.l.repair_token(t['ticket'],'yanhul/AIOS','b'*40,'f'*64)
    def test_no_direct_diagnosed_to_act(self):
        t,nonce=self.l.create(self.event())
        with self.assertRaises(PermissionError): self.l.repair_token(t['ticket'],'yanhul/AIOS','a'*40,'f'*64)
    def test_expired_ticket_rejected(self):
        t,nonce=self.l.create(self.event(),ttl=1); self.l.db.execute('UPDATE tickets SET expires_at=? WHERE ticket=?',(int(time.time())-1,t['ticket'])); self.l.db.commit()
        with self.assertRaises(PermissionError): self.l.command('+84123456789',f'SUA {t["ticket"]} {nonce}',True,'f'*64)
        self.assertEqual(self.l.get(t['ticket'])['status'],'EXPIRED')
    def test_stop_revokes_pending(self):
        t,nonce=self.l.create(self.event()); out=self.l.command('+84123456789','STOP',True)
        self.assertEqual(out['revoked'],1); self.assertEqual(self.l.get(t['ticket'])['status'],'REVOKED')
    def test_repair_token_is_bound_and_one_time(self):
        t=self.authorize(); auth=self.l.repair_token(t['ticket'],'yanhul/AIOS','a'*40,'f'*64)
        self.assertEqual(self.l.get(t['ticket'])['status'],'ACTING')
        out=self.l.consume_repair_token(auth['authorization_token'],t['ticket'],'yanhul/AIOS','a'*40,'f'*64)
        self.assertEqual(out['effect'],'repair')
        with self.assertRaises(PermissionError): self.l.consume_repair_token(auth['authorization_token'],t['ticket'],'yanhul/AIOS','a'*40,'f'*64)
    def test_stop_revokes_authorized_before_worker_claim(self):
        t=self.authorize(); out=self.l.command('+84123456789','STOP',True)
        self.assertEqual(out['revoked'],1)
        with self.assertRaises(PermissionError): self.l.repair_token(t['ticket'],'yanhul/AIOS','a'*40,'f'*64)
    def test_protocol_shape(self):
        with open('protocol.json',encoding='utf-8') as f: p=json.load(f)
        self.assertTrue(p['authorization']['replay_rejected']); self.assertEqual(p['commands']['RETRY']['effect'],'retry_verify_only')

if __name__=='__main__': unittest.main()
