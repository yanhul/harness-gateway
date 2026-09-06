#!/usr/bin/env python3
"""Minimal stdlib-only human authorization gateway.

The gateway never writes to target repositories. A repair worker must consume the
narrow authorization record produced here and perform its own governance checks.
"""
from __future__ import annotations
import hashlib, hmac, json, os, re, secrets, sqlite3, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

REPOS = {"yanhul/AIOS", "yanhul/try", "yanhul/android-ai-assistant", "yanhul/RX50"}
ALLOWED_TRANSITIONS = {
    "OBSERVED":{"DIAGNOSED","BLOCKED"}, "DIAGNOSED":{"AWAITING_HUMAN","BLOCKED"},
    "AWAITING_HUMAN":{"AUTHORIZED","REJECTED","EXPIRED","REVOKED","BLOCKED"},
    "AUTHORIZED":{"ACTING","REVOKED","BLOCKED"}, "ACTING":{"VERIFYING","BLOCKED"},
    "VERIFYING":{"PERSISTED","BLOCKED"}, "PERSISTED":{"RESUMED","BLOCKED"},
}
TICKET_RE = re.compile(r"^[A-Z0-9_-]{8,80}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def now() -> int: return int(time.time())
def digest(v: str) -> str: return hashlib.sha256(v.encode()).hexdigest()


def normalize_workflow_run(payload: dict[str, Any]) -> dict[str, Any]:
    """Convert a GitHub workflow_run webhook into the strict internal contract."""
    wr = payload.get("workflow_run")
    if not isinstance(wr, dict): raise ValueError("missing workflow_run")
    repo_obj = payload.get("repository")
    full_name = repo_obj.get("full_name") if isinstance(repo_obj, dict) else None
    run_id = wr.get("id")
    sha = wr.get("head_sha")
    workflow = wr.get("name")
    conclusion = wr.get("conclusion")
    run_url = wr.get("html_url")
    if not isinstance(full_name,str) or not isinstance(workflow,str) or not isinstance(run_url,str):
        raise ValueError("invalid repository/workflow/url")
    if full_name not in REPOS: raise ValueError("repository not authorized")
    if not isinstance(run_id,int) or run_id <= 0 or not isinstance(sha,str) or not SHA_RE.fullmatch(sha):
        raise ValueError("invalid run identity")
    if not run_url.startswith(f"https://github.com/{full_name}/actions/runs/{run_id}"):
        raise ValueError("invalid run_url")
    gov = payload.get("governance_digest")
    if not isinstance(gov,str) or not DIGEST_RE.fullmatch(gov):
        raise ValueError("missing governance_digest")
    return {
        "repo":full_name,"workflow":workflow,"run_id":run_id,"head_sha":sha,
        "conclusion":conclusion,"run_url":run_url,"governance_digest":gov,
        "failure":payload.get("failure","ci_failure"),
        "diagnosis":payload.get("diagnosis",""),
        "proposed_action":payload.get("proposed_action","repair implementation"),
    }

class Ledger:
    def __init__(self, path: str = "gateway.db"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS tickets(
          ticket TEXT PRIMARY KEY, event_key TEXT UNIQUE NOT NULL, repo TEXT NOT NULL,
          workflow TEXT NOT NULL, run_id INTEGER NOT NULL, head_sha TEXT NOT NULL,
          failure TEXT NOT NULL, diagnosis TEXT NOT NULL, proposed_action TEXT NOT NULL,
          governance_digest TEXT NOT NULL, nonce_hash TEXT NOT NULL, status TEXT NOT NULL,
          created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, nonce_used INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT, event TEXT NOT NULL,
          actor TEXT NOT NULL, payload TEXT NOT NULL, created_at INTEGER NOT NULL,
          prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS governance(ticket TEXT NOT NULL, name TEXT NOT NULL,
          digest TEXT NOT NULL, PRIMARY KEY(ticket,name));
        CREATE TABLE IF NOT EXISTS repair_authorizations(
          token_hash TEXT PRIMARY KEY, ticket TEXT UNIQUE NOT NULL, repo TEXT NOT NULL,
          head_sha TEXT NOT NULL, governance_digest TEXT NOT NULL,
          issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
        """)
        self.db.commit()

    def _event(self, ticket: str|None, event: str, actor: str, payload: dict[str,Any]):
        row = self.db.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        prev = row[0] if row else "0"*64
        body = json.dumps(payload, sort_keys=True, separators=(",",":"))
        eh = digest(prev + event + actor + body)
        self.db.execute("INSERT INTO events(ticket,event,actor,payload,created_at,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?)",
                        (ticket,event,actor,body,now(),prev,eh))

    def _transition(self,ticket,new,actor):
        row=self.db.execute("SELECT status FROM tickets WHERE ticket=?",(ticket,)).fetchone()
        if not row or new not in ALLOWED_TRANSITIONS.get(row[0],set()): raise PermissionError(f"illegal transition {row[0] if row else None}->{new}")
        self.db.execute("UPDATE tickets SET status=? WHERE ticket=?",(new,ticket)); self._event(ticket,"STATE",actor,{"from":row[0],"to":new})

    def create(self, p: dict[str,Any], ttl: int = 900):
        repo, wf, run_id, sha, gov = p.get("repo"), p.get("workflow"), p.get("run_id"), p.get("head_sha"), p.get("governance_digest")
        if repo not in REPOS or not isinstance(wf,str) or not wf.strip() or not isinstance(run_id,int) or run_id <= 0 or not isinstance(sha,str) or not SHA_RE.fullmatch(sha): raise ValueError("invalid webhook identity")
        if p.get("conclusion") not in ("failure","timed_out","cancelled"): raise ValueError("not a repair-triggering failure")
        if not isinstance(gov,str) or not DIGEST_RE.fullmatch(gov): raise ValueError("missing governance_digest")
        run_url=p.get("run_url")
        if not isinstance(run_url,str) or not run_url.startswith(f"https://github.com/{repo}/actions/runs/{run_id}"): raise ValueError("invalid run_url")
        key = f"{repo}|{wf}|{run_id}|{sha}"
        existing = self.db.execute("SELECT * FROM tickets WHERE event_key=?", (key,)).fetchone()
        if existing: return dict(existing), False
        ticket = p.get("ticket") or f"{repo.split('/')[-1].upper()}-{time.strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
        if not isinstance(ticket,str) or not TICKET_RE.fullmatch(ticket): raise ValueError("invalid ticket")
        nonce = secrets.token_urlsafe(9); t = now(); exp = t + max(1,ttl)
        self.db.execute("INSERT INTO tickets VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ticket,key,repo,wf,run_id,sha,p.get("failure","ci_failure"),p.get("diagnosis",""),p.get("proposed_action","repair implementation"),gov,digest(nonce),"OBSERVED",t,exp,0))
        self._event(ticket,"TICKET_CREATED","github-webhook",{"event_key":key,"repo":repo,"workflow":wf,"run_id":run_id,"head_sha":sha})
        self._transition(ticket,"DIAGNOSED","gateway")
        self._transition(ticket,"AWAITING_HUMAN","gateway")
        self.db.commit()
        return dict(self.db.execute("SELECT * FROM tickets WHERE ticket=?",(ticket,)).fetchone()), nonce

    def get(self,ticket):
        r=self.db.execute("SELECT * FROM tickets WHERE ticket=?",(ticket,)).fetchone()
        return dict(r) if r else None

    def command(self, sender: str, text: str, gateway_token_ok: bool, governance_digest: str|None=None):
        if not gateway_token_ok: raise PermissionError("gateway authentication failed")
        allowed = {x.strip() for x in os.getenv("AUTHORIZED_PHONE","").split(",") if x.strip()}
        if not allowed or sender not in allowed: raise PermissionError("sender not authorized")
        parts=text.strip().split()
        if not parts: raise ValueError("empty command")
        cmd=parts[0].upper()
        if cmd == "STATUS": return [dict(r) for r in self.db.execute("SELECT ticket,repo,head_sha,status,expires_at FROM tickets ORDER BY created_at DESC LIMIT 20")]
        if cmd == "STOP":
            rows=self.db.execute("SELECT ticket FROM tickets WHERE status IN ('AWAITING_HUMAN','AUTHORIZED')").fetchall()
            for r in rows: self._transition(r[0],"REVOKED",sender)
            self.db.commit(); return {"revoked":len(rows)}
        if cmd not in {"SUA","BOQUA","RETRY"} or len(parts) < 2: raise ValueError("invalid command")
        ticket=parts[1]
        if not TICKET_RE.fullmatch(ticket): raise ValueError("invalid ticket")
        row=self.get(ticket)
        if not row: raise ValueError("unknown ticket")
        if now() > row["expires_at"] and row["status"] in {"AWAITING_HUMAN","AUTHORIZED"}:
            self._transition(ticket,"EXPIRED","gateway"); self.db.commit(); raise PermissionError("ticket expired")
        if cmd == "BOQUA":
            self._transition(ticket,"REJECTED",sender); self.db.commit(); return {"ticket":ticket,"status":"REJECTED"}
        if cmd == "RETRY":
            if row["status"] not in {"AWAITING_HUMAN","AUTHORIZED","BLOCKED"}: raise PermissionError("retry not allowed")
            self._event(ticket,"VERIFY_ONLY","human",{"sender":sender}); self.db.commit(); return {"ticket":ticket,"effect":"retry_verify_only"}
        if len(parts)!=3: raise ValueError("SUA requires ticket and nonce")
        if row["status"] != "AWAITING_HUMAN": raise PermissionError("ticket not awaiting human")
        if row["nonce_used"]: raise PermissionError("nonce replay")
        if not hmac.compare_digest(digest(parts[2]),row["nonce_hash"]): raise PermissionError("bad nonce")
        if governance_digest != row["governance_digest"]:
            self._transition(ticket,"BLOCKED",sender); self.db.commit(); raise PermissionError("governance digest mismatch")
        self.db.execute("UPDATE tickets SET nonce_used=1 WHERE ticket=?",(ticket,))
        self._transition(ticket,"AUTHORIZED",sender); self.db.commit()
        return {"ticket":ticket,"status":"AUTHORIZED","repo":row["repo"],"head_sha":row["head_sha"],"governance_digest":row["governance_digest"]}

    def repair_token(self,ticket, repo, sha, gov):
        row=self.get(ticket)
        if not row or row["status"] != "AUTHORIZED": raise PermissionError("repair not authorized")
        if row["repo"] != repo or row["head_sha"] != sha or row["governance_digest"] != gov: raise PermissionError("authorization binding mismatch")
        existing=self.db.execute("SELECT 1 FROM repair_authorizations WHERE ticket=?",(ticket,)).fetchone()
        if existing: raise PermissionError("repair authorization already issued")
        raw=secrets.token_urlsafe(32); t=now(); exp=min(row["expires_at"],t+300)
        self.db.execute("INSERT INTO repair_authorizations VALUES(?,?,?,?,?,?,?,0)",
                        (digest(raw),ticket,repo,sha,gov,t,exp))
        self._transition(ticket,"ACTING","repair-worker")
        self._event(ticket,"REPAIR_AUTH_ISSUED","gateway",{"repo":repo,"head_sha":sha,"expires_at":exp})
        self.db.commit()
        return {"ticket":ticket,"repo":repo,"head_sha":sha,"governance_digest":gov,"authorization_token":raw,"expires_at":exp,"effect":"repair"}

    def consume_repair_token(self, raw, ticket, repo, sha, gov):
        if not isinstance(raw,str) or not raw: raise PermissionError("missing authorization token")
        row=self.db.execute("SELECT * FROM repair_authorizations WHERE token_hash=?",(digest(raw),)).fetchone()
        if not row or row["consumed"]: raise PermissionError("invalid or replayed authorization token")
        if now() > row["expires_at"]: raise PermissionError("authorization token expired")
        if row["ticket"] != ticket or row["repo"] != repo or row["head_sha"] != sha or row["governance_digest"] != gov: raise PermissionError("authorization binding mismatch")
        self.db.execute("UPDATE repair_authorizations SET consumed=1 WHERE token_hash=?",(digest(raw),))
        self._event(ticket,"REPAIR_AUTH_CONSUMED","repair-worker",{"repo":repo,"head_sha":sha})
        self.db.commit()
        return {"ticket":ticket,"repo":repo,"head_sha":sha,"governance_digest":gov,"effect":"repair"}


def verify_github_signature(body: bytes, signature: str, secret: str) -> bool:
    if not signature.startswith("sha256="): return False
    expected="sha256="+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected,signature)

class Handler(BaseHTTPRequestHandler):
    ledger: Ledger = None  # type: ignore
    def _json(self,code,obj):
        raw=json.dumps(obj,separators=(",",":"),sort_keys=True).encode(); self.send_response(code); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        if self.path == "/health": return self._json(200,{"ok":True})
        return self._json(404,{"error":"not_found"})
    def do_POST(self):
        n=int(self.headers.get("Content-Length","0")); body=self.rfile.read(n)
        try:
            if self.path == "/github/webhook":
                secret=os.environ.get("GITHUB_WEBHOOK_SECRET","")
                if not secret or not verify_github_signature(body,self.headers.get("X-Hub-Signature-256",""),secret): return self._json(401,{"error":"bad_signature"})
                p=json.loads(body); p=normalize_workflow_run(p); r=self.ledger.create(p)
                return self._json(200,{"accepted":True,"ticket":r[0]["ticket"],"new":bool(r[1])})
            if self.path == "/sms/command":
                token=self.headers.get("X-Gateway-Token",""); expected=os.environ.get("ANDROID_GATEWAY_TOKEN","")
                ok=bool(expected) and hmac.compare_digest(token,expected)
                p=json.loads(body); out=self.ledger.command(self.headers.get("X-SMS-Sender",""),p["text"],ok,p.get("governance_digest")); return self._json(200,out)
            if self.path == "/repair/authorize":
                token=self.headers.get("X-Repair-Worker-Token",""); expected=os.environ.get("REPAIR_WORKER_TOKEN","")
                if not expected or not hmac.compare_digest(token,expected): return self._json(401,{"error":"unauthorized"})
                p=json.loads(body); raw=p.get("authorization_token")
                if raw:
                    return self._json(200,self.ledger.consume_repair_token(raw,p["ticket"],p["repo"],p["head_sha"],p["governance_digest"]))
                return self._json(200,self.ledger.repair_token(p["ticket"],p["repo"],p["head_sha"],p["governance_digest"]))
            return self._json(404,{"error":"not_found"})
        except (ValueError,PermissionError,KeyError,json.JSONDecodeError) as e: return self._json(400,{"error":str(e)})


def main():
    host=os.getenv("HOST","127.0.0.1"); port=int(os.getenv("PORT","8080")); db=os.getenv("GATEWAY_DB","gateway.db")
    Handler.ledger=Ledger(db); print(f"harness-gateway listening on {host}:{port}"); ThreadingHTTPServer((host,port),Handler).serve_forever()
if __name__ == "__main__": main()
