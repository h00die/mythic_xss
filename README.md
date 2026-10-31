# CVE-2026-119764

## Vulnerability

Mythic (open-source command-and-control framework) v3.2.16 through v3.4.0.61 contains a stored Cross-Site Scripting vulnerability (CWE-79, aided by CWE-693 missing security headers) in the operator web UI that allows an attacker to take over a Mythic operator's account, including administrators, and thereby read all callback data, credentials, and tasking for every operation hosted on the instance. CVSS 3.1: 8.6 High - AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N.

Mythic stores every file an agent uploads (the output of operator-initiated `download` tasks) on the server WITHOUT a file extension, under ./files/<uuid> (mythic-docker/src/rabbitmq/utils.go, GetSaveFilePath). The UI's file-preview route, GET /direct/view/<agent_file_id> (registered in mythic-docker/src/webserver/initialize.go:181 behind CookieAuthMiddleware), serves that file with gin's c.File() (mythic-docker/src/webserver/controllers/file_direct_view.go:57,61). Because the on-disk name has no extension, Go's net/http content-sniffs the first 512 bytes of ATTACKER-CONTROLLED content and returns "Content-Type: text/html; charset=utf-8", inline, same-origin. Neither the nginx front (nginx-docker/services.conf.template contains zero add_header directives) nor the Go server sets a Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options, or HSTS.

The operator UI then embeds that same URL in a same-origin nested browsing context: for files whose agent-reported name ends in .pdf, the "Preview Media" action renders <object data={"/direct/view/" + agent_file_id}> (MythicReactUI/src/components/pages/Callbacks/ResponseDisplayMedia.js:336; reachable from the callback File Browser table, the tasking output view, the file search page, download history, and the file context menu). Any HTML/JavaScript in the uploaded bytes therefore executes as the authenticated Mythic UI origin. The UI keeps the operator's long-lived JWT access_token and refresh_token in localStorage (MythicReactUI/src/cache.js:168-169), so the injected script simply reads both tokens and exfiltrates them. The stolen JWT grants full GraphQL + REST access as that operator: all callbacks across every operation, the credential store, tasking rights; an admin token additionally allows persistent access via apitoken/operator creation.

## Impact

Complete compromise of the Mythic operator console and, through it, the entire C2 deployment: all implanted endpoints, collected credentials, and past/present tasking for every operation become readable and controllable by the attacker. The stolen session is a valid JWT, so the attacker needs no further interaction with the operator's browser.

The attacker position required is minimal and realistic: control or visibility of ANY endpoint the operator will exfiltrate files from (a defender-run IR station that seized an implant host, a honeypot, a co-tenanted machine). The attacker never communicates with the Mythic server, never speaks the agent protocol, never needs a payload UUID or encryption key, and plants no software on the operator side. The only user interaction is one routine UI click the operator initiates themselves (Preview Media on a file they chose to download). This is the same vulnerability class as CVE-2022-39197 (Cobalt Strike <=4.7, exploited in the wild, CISA KEV): operator-trusted data rendered as HTML in the privileged C2 client.

## Affected versions

Introduced in v3.2.16 (commit e80fe952 adds both the /direct/view route and the <object> embed in the same release). Verified present in v3.2.16-v3.2.20, all v3.3.0.x releases (v3.3.0.0 through v3.3.0.136), and all v3.4.0.x releases (v3.4.0.0 through v3.4.0.61, the final v3 release; no backport exists). Versions through v3.2.2 are not affected (no /direct/view route). Fixed in v4.0.0 (fix present from the first release candidate v4.0.0rc1): the route moved behind Authorization-header JWT authentication with a file-read token scope, so the cookie-authenticated embed request can no longer retrieve file content. Recommended fix for any v3 deployment: pin Content-Type (e.g. application/octet-stream + Content-Disposition: attachment) or an isolated preview origin, add nosniff/CSP globally, and scope file-serving routes to the caller's operation.

## Step-by-step reproduction

Lab setup (vulnerable version):

1. git clone https://github.com/its-a-feature/Mythic && cd Mythic && git checkout v3.4.0.61
2. Install and start the stack (Kali example): `sudo ./install_docker_kali.sh && sudo ./mythic-cli start` (or build mythic-cli from Mythic_CLI with cargo and use `./mythic-cli` start). The UI is served at https://127.0.0.1:7443; log in with the admin credentials printed by `./mythic-cli` or found in the generated .env.
3. Install an agent and C2 profile: `./mythic-cli install github https://github.com/MythicC2Profiles/http -f && ./mythic-cli install github https://github.com/MythicAgents/medusa -f`
4. In the UI (Create Payload): build a medusa payload with the http profile, encryption aes256_hmac or none; deploy/execute it on a host you control (this plays the "attacker-controlled endpoint the operator has a callback on") and confirm the callback appears in the UI.

Attack:

5. On the endpoint that has the callback (attacker side), run the PoC kit (python3 + requests):
   `./hostile_endpoint_xss.py --plant /srv/HR_Shared --listen 0.0.0.0:8443`
   This writes /srv/HR_Shared/salaries_2026.pdf, a file whose NAME ends in .pdf but whose BYTES are an HTML document containing a script that reads localStorage access_token/refresh_token and POSTs them to the listener (and starts an automatic post-exploitation module as soon as the tokens arrive).
6. Operator side (normal behavior): in the callback's interactive console, task `download /srv/HR_Shared/salaries_2026.pdf`. The genuine, unmodified agent uploads the file into Mythic; the server stores it extension-less and lists it in the file browser.
7. Operator side: open the callback's File Browser tab, expand the folder, click the Preview Media icon on the salaries_2026.pdf row. The UI renders `<object data="/direct/view/<id>">;` the server sniffs the bytes as text/html and serves them inline same-origin; the script runs in the operator UI origin and exfiltrates the tokens.
8. Attacker side observes: the listener prints the captured tokens and then authenticates to Mythic AS the operator (identity, operation membership, all callbacks, credential store), e.g.:
   [+] planted /srv/HR_Shared/salaries_2026.pdf (1386 bytes)
   [+] operator browser called back: /loot
   [+] captured operator tokens -> loot_route1.json
   [+] authenticated AS OPERATOR: user_id=1 in operation "Operation Chimera"
   [+] stolen session belongs to: mythic_admin (admin=True)

Server-side confirmation without a browser (single curl, shows the mis-served content type):

  `curl -sk -i -H "Cookie: mythic=<operator jwt>" https://127.0.0.1:7443/direct/view/<agent_file_id>`
  -> HTTP/1.1 200 OK
  -> Content-Type: text/html; charset=utf-8      (should be application/octet-stream + attachment)
  -> <the HTML/JS payload bytes, no CSP, no X-Content-Type-Options anywhere>

Operator-side browser automation of steps 6-7 (headless Chromium via Playwright) is included as poc/operator_browser_poc.py; the full chain was verified end-to-end against a stock v3.4.0.61 stack with an unmodified medusa agent.

## Proof of concept

Self-contained Python PoC kit (python3 + requests, no Mythic source or agent code needed): hostile_endpoint_xss.py plants the polyglot document, runs the exfil listener, and performs authenticated post-exploitation with the stolen tokens. A second exploit, mythic_direct_view_xss.py, demonstrates an alternate delivery vector where a hostile implant speaks the agent protocol itself (payload UUID + key are embedded in every deployed implant binary). The PoC repository will be published at https://github.com/h00die/mythic_3.4_xss after the CVE is assigned (available to the CNA on request). All testing was performed against the reporter's own lab instances.
