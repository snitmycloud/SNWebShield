# SNWebShield demo script

**Goal:** show that anyone can add their own website, prove they own it, and get a clear security report in about a minute.
Everything runs on this computer. Screenshots of every step are in `docs/proof/demo/` (use them if anything fails live).

## 0. Before the demo (10 minutes)

1. Open a PowerShell window and start everything:

   ```powershell
   cd C:\SNWebShield-Local
   powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1
   ```

   It starts the API (port 8000), the scan worker and the web app (port 5173), skips what is already running, and prints
   `API OK` and `Web app OK`. The extra Nuclei checks stay **off** (they are optional; nothing in the demo depends on them).
   To stop everything afterwards: `powershell -ExecutionPolicy Bypass -File scripts\stop-demo.ps1`.
2. Open **http://127.0.0.1:5173** in Chrome.
3. Demo accounts (made for the demo, not real people). The passwords are in the private file
   `C:\Users\nalav\SNWebShield-Private\demo-accounts.json` (outside the repository; never paste them into chat or a slide):

   | Account | Email | Use it to |
   |---|---|---|
   | Administrator | `demo-admin@example.com` | show the results already prepared (scanme), and **verify an evaluator's site manually** if their DNS cannot be changed during the demo |
   | Normal user | `demo-user@example.com` | show what a customer sees (no manual-verify button) |
4. Sign in as the administrator and check the dashboard shows the **scanme.nmap.org** card with a grade (a fresh scan is already there).
5. Only scan websites we are allowed to: `scanme.nmap.org` (published for testing) and the GitHub Pages test site, or a website whose
   owner is present and agrees.

## 1. The story (say this first, 30 seconds)

> "SNWebShield checks a website for security weaknesses and explains them in plain language. We only ever scan a website after its
> owner has proved they own it. Let me show you with a real site."

## 2. Show a finished scan (scanme.nmap.org) — 2 minutes

| Click | Say |
|---|---|
| **Dashboard** | "Each website is a card: a grade from A to F, the score out of 100, and when the certificate expires." Point at **C 73/100** on the scanme card. |
| Click the **scanme.nmap.org** card | "This is a site published by the Nmap project for scanning practice, so we may test it." |
| **Monitor** tab | "Last scan, how long it took (under a minute), certificate, and the score." |
| **Detect** tab | "What we found from the outside: open ports in plain words, the software and versions, email and DNS settings, exposed files." |
| **Vulnerabilities** tab | "Confirmed findings first, in colour. Below, **Needs checking**: known problems for the software version we saw, but this server is Ubuntu, and Ubuntu often fixes problems without changing the version number. We say so, and show the command to check, instead of guessing." |
| **Report** tab → **Download PDF** | "One page you can hand to your boss or your hosting company. For every finding: what you have, what you should have, the risk and how to fix it. In the print window choose **Save as PDF**." |

## 3. Evaluator's own website — the main demo (3 minutes)

1. **Websites** → type the evaluator's domain (for example `www.theirsite.com`) → **Add website**.
   *Say:* "Adding a website does not scan it. We first need proof that it is theirs."
2. The page shows **Prove you own …** with three ways: **DNS TXT record**, **Upload a file**, **Homepage meta tag**.
   *Say:* "Pick the easiest. Every value has a **Copy** button, and the steps are numbered." (DNS is fastest for people who manage their domain; the file method needs HTTPS.)
3. When they have added it, click **Check now** (it becomes **Check again** if it is not found yet).
   *If their site sends `example.com` and `www.example.com` to each other, say:* "That is fine: we check both and explain what we found."
4. **If their DNS or hosting cannot be changed right now (backup):** as the **administrator**, click **Verify manually (admin)**,
   type a reason such as `Owner present at demo and gave consent`, and click **Verify for 24 hours**.
   *Say:* "Administrators only, a reason is required, it lasts 24 hours, it is labelled **Manually verified by admin**, and it is written to the audit log. A normal user cannot do this."
5. The first scan starts automatically. Watch the live progress line (ports → versions → technologies → files → DNS → settings → vulnerabilities).
   *Say:* "Under three minutes for a normal site. Results appear as they arrive; the vulnerability database can be slow without an API key, and the page never blocks."
6. Open **Vulnerabilities** and **Report**; show the **grade**, then **Download PDF**.
7. **Dashboard**: the new card with its score.

## 4. What to say about the results

- "**Confirmed** means we checked it ourselves. **Needs checking** means it might apply; it does not lower the score until confirmed."
- "A good score is not a guarantee. We never say a site is 'safe', only what we found and what we could not check."
- If the site is behind a CDN (Cloudflare, Akamai, Fastly …) a note appears: **"This site is behind Cloudflare. Port results show the CDN, not your server."**
- If a site blocks scanners or redirects to `www`, a note explains it in plain language.
- IPv6-only websites show "not supported yet".

## 5. If something goes wrong

| Problem | What to do |
|---|---|
| Page does not load | Run `scripts\start-demo.ps1` again; it only starts what is missing. |
| The evaluator's DNS change is not visible yet | Wait a minute and press **Check again**, or use **Verify manually (admin)**. |
| A scan is slow | It keeps running; partial results appear. The "Subdomain list unavailable" note is normal when the outside service is slow and does not affect the score. |
| "Scan limit" message | The scanme test target allows 10 scans a day. Use the prepared results. |
| Anything else | Show the screenshots in `docs/proof/demo/`. |

## 6. Safety points to mention if asked

- We scan only after ownership is proved (DNS TXT, a file or a meta tag), and re-check it before every scan.
- We never contact private or internal addresses; one address is pinned per scan.
- A check that fails or times out is reported as **could not check**, never as clean.
- No passwords, keys or file contents are stored; cookie values are never kept.
- The optional extra checks (Nuclei) are off by default and run only behind a firewall rule and a self-test.
