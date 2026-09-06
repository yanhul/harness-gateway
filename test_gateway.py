import hashlib, hmac, json, os, tempfile, unittest
from gateway import Ledger, verify_github_signature

class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.NamedTemporaryFile(delete=False); self.tmp.close()
        self.l=Ledger(self.tmp.name); os.environ['AUTHORIZED_PHONE']='+84123456789'
    def tearDown(self): os.unlink(self.tmp.name)
    def event(self):
        return {'repo':'yanhul/AIOS','workflow':'CI','run_id':123,'head_sha':'a'*40,
                'conclusion':'failure','failure':'test_failure','diagnosis':'x',
                'proposed_action':'patch implementation','governance_digest':'g'*64}
    def test_signature(self):
        b=b'{}'; s=hmac.new(b'secret',b,hashlib.sha256).hexdigest()
        self.assertTrue(verify_github_signature(b,'sha256='+s,'secret'))
        self.assertFalse(verify_github_signature(b,'sha256='+('0'*64),'secret'))
    def ticket(self): return self.l.create(self.event())[0]
    def test_duplicate_event_idempotent(self):
        a=self.l.create(self.event()); b=self.l.create(self.event())
        self.assertEqual(a[0]['ticket'],b[0]['ticket']); self.assertFalse(b[1])
    def test_wrong_sender_rejected(self):
        t,nonce=self.l.create(self.event())
        with self.assertRaises(PermissionError): self.l.command('+84000000000',f'SUA {t["ticket"]} {nonce}',True,'g'*64)
    def test_wrong_nonce_rejected(self):
        t,nonce=self.l.create(self.event())
        with self.assertRaises(PermissionError): self.l.command('+84123456789',f'SUA {t["ticket"]} bad',True,'g'*64)
    def test_nonce_replay_rejected(self):
        t,nonce=self.l.create(self.event())
        self.l.command('+84123456789',f'SUA {t["ticket"]} {nonce}',True,'g'*64)
        with self.assertRaises(PermissionError): self.l.command('+84123456789',f'SUA {t["ticket"]} {nonce}',True,'g'*64)
    def test_governance_mismatch_blocks(self):
        t,nonce=self.l.create(self.event())
        with self.assertRaises(PermissionError): self.l.command('+84123456789',f'SUA {t["ticket"]} {nonce}',True,'x'*64)
        self.assertEqual(self.l.get(t['ticket'])['status'],'BLOCKED')
    def test_sha_binding(self):
        t,nonce=self.l.create(self.event()); self.l.command('+84123456789',f'SUA {t["ticket"]} {nonce}',True,'g'*64)
        with self.assertRaises(PermissionError): self.l.repair_token(t['ticket'],'yanhul/AIOS','b'*40,'g'*64)
    def test_no_direct_diagnosed_to_act(self):
        t,nonce=self.l.create(self.event())
        with self.assertRaises(PermissionError): self.l.repair_token(t['ticket'],'yanhul/AIOS','a'*40,'g'*64)
    def test_stop_revokes_pending(self):
        t,nonce=self.l.create(self.event())
        out=self.l.command('+84123456789','STOP',True)
        self.assertEqual(out['revoked'],1); self.assertEqual(self.l.get(t['ticket'])['status'],'REVOKED')
    def test_protocol_shape(self):
        p=json.load(open('protocol.json'))
        self.assertTrue(p['authorization']['replay_rejected'])
        self.assertEqual(p['commands']['RETRY']['effect'],'retry_verify_only')

if __name__=='__main__': unittest.main()
