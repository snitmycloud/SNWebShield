// Draft legal text. EVERY page is marked "DRAFT – needs legal review" and must be reviewed by a lawyer before launch.
// Items in [PLACEHOLDER: ...] brackets are details the owner still has to supply.

export const DRAFT_NOTICE = "DRAFT – needs legal review";

export function legalPages(c, domain) {
  const p = c.placeholders;
  const who = `${c.company} (“we”, “us”), the operator of ${c.product}`;
  return {
    terms: {
      title: "Terms of Service",
      path: "terms",
      description: `The terms for using ${c.product}, a website security scanner for websites you own.`,
      sections: [
        ["1. About these terms", [`These terms apply when you use ${c.product} at ${domain}. The service is run by ${who}, ${c.address}. Company registration: ${p.companyRegistration}. By creating an account you agree to these terms. If you do not agree, do not use the service.`]],
        ["2. What the service does", [`${c.product} checks websites you own for common security problems and tells you what it found. It reports findings from automated checks. It never says a website is “safe” or “secure”: a clean result means the checks we ran found nothing, not that nothing is wrong. Checks that fail or time out are shown as “could not check”.`]],
        ["3. You may only scan what you own", [`We only scan a website after you prove you control it, using a DNS record, a file on the site or a tag in its homepage. You must be the owner, or have the owner’s written permission to scan it and to verify it. If you lose control of the website, scans stop. Scanning a website you do not own or have no permission to test is forbidden. See the Acceptable Use Policy.`]],
        ["4. Your account", [`You must give a correct email address and keep your password private. You are responsible for what happens under your account. Tell us at ${c.contactEmail} if you think someone else has used it.`]],
        ["5. Plans, payment and cancellation", [`There is a Free plan and paid plans. Prices and limits are shown on the pricing section of our website. Paid plans are billed through our payment partner (Razorpay) when payments are enabled. You can cancel at any time; a paid plan then stays active until the end of the period you paid for. If a payment fails or a plan ends, your account returns to the Free plan. Your data is kept; websites above the Free limit become read-only (no new scans or monitoring) and are not deleted. Taxes such as GST are shown at checkout where they apply. Refunds: [PLACEHOLDER: refund policy].`]],
        ["6. No guarantee", [`Security testing cannot find every problem. We give the service “as is” and do not promise that it will find all weaknesses, that it will always be available, or that it is suitable for a particular purpose. You remain responsible for fixing issues and for the security of your own website.`]],
        ["7. Limit of liability", [`To the extent the law allows, we are not liable for indirect or consequential loss, lost profit or lost data. Our total liability for any claim is limited to the amount you paid us in the 12 months before the claim. [PLACEHOLDER: lawyer to confirm limits that apply under Indian law.]`]],
        ["8. Suspension and ending", [`We may suspend or close an account that breaks these terms or the Acceptable Use Policy, or that puts the service or other people at risk. You can close your account at any time by writing to ${c.contactEmail}.`]],
        ["9. Changes", [`We may change these terms. If a change matters, we will tell you by email or in the service before it applies. Using the service after that means you accept the new terms.`]],
        ["10. Law and disputes", [`These terms are governed by the laws of India. The courts at ${p.governingCity} have jurisdiction, subject to applicable law. [PLACEHOLDER: lawyer to confirm.]`]],
        ["11. Contact", [`${c.company}, ${c.address}. Email: ${c.contactEmail}. Phone: ${p.phone}.`]],
      ],
    },
    privacy: {
      title: "Privacy Policy",
      path: "privacy",
      description: `What personal data ${c.product} collects, why, and what rights you have.`,
      sections: [
        ["1. Who we are", [`${who}, ${c.address}, is responsible for your personal data. Contact: ${c.contactEmail}. Grievance officer: ${p.grievanceOfficer}.`]],
        ["2. What we collect", [
          `Account data: your name (if you give it), email address and a password stored only as a salted hash (we never keep or see the password itself).`,
          `Website data: the domains you add, proof of ownership you set up, scan results, findings, scores, uptime checks and the actions you take on them (for example “accepted risk”).`,
          `Security and audit records: sign-in outcomes, ownership checks, scans (who, which website, when, result) and administrator actions. These records are kept to protect you and the service.`,
          `Payment data (when paid plans are enabled): handled by Razorpay. We receive the plan, amount, status and invoice details. We never receive or store your card, UPI or bank details.`,
          `Technical data: your IP address and basic request information in server logs.`]],
        ["3. Why we use it", [`To run the service you asked for (sign-in, scans, alerts, reports), to keep it secure, to send you emails about your account and the alerts you turned on, to bill paid plans, and to meet legal duties. We do not sell your data and we do not use your scan results for advertising.`]],
        ["4. Who sees it", [`Only you and our authorised administrators. Service providers who help us run the service (hosting, email delivery, Razorpay for payments) process data on our behalf under their own terms. We share data with authorities only when the law requires it.`]],
        ["5. How long we keep it", [`Scan history is kept for the number of days in your plan. Audit records are kept [PLACEHOLDER: audit retention period]. Invoices are kept as long as tax law requires. When you ask us to close your account we delete or anonymise your personal data, except records we must keep by law.`]],
        ["6. Your rights", [`Under India’s Digital Personal Data Protection Act, 2023 you can ask us to give you a summary of your data, correct it, erase it, and you can withdraw consent or complain to us. Write to ${c.contactEmail}; we will reply within [PLACEHOLDER: response time]. You may also complain to the Data Protection Board of India. [PLACEHOLDER: lawyer to confirm the wording.]`]],
        ["7. Cookies and storage", [`We do not use advertising or tracking cookies. The website keeps your light/dark choice, and the app keeps your sign-in for the browser session, in your browser’s own storage.`]],
        ["8. Security", [`Passwords are hashed, traffic is protected in transit, accounts lock after repeated failed sign-ins, and access is limited. No system is perfectly secure; we will tell you and the authorities if a breach affecting you happens, as the law requires.`]],
        ["9. Children", [`The service is for adults. It is not meant for children under 18.`]],
        ["10. Changes", [`We will post changes here and tell you by email if they matter. Effective date: ${p.effectiveDate}.`]],
      ],
    },
    "acceptable-use": {
      title: "Acceptable Use Policy",
      path: "acceptable-use",
      description: `The rules for using ${c.product}: scan only what you own, and nothing that harms others.`,
      sections: [
        ["1. The one rule", [`Only scan websites you own, or that the owner has given you written permission to test. The service enforces this: it will not scan a website until you have proved control of it, and it stops if you lose control.`]],
        ["2. You must not", [
          `Add a website you do not own or have no permission to test, or fake the proof of ownership.`,
          `Use the service to attack, disrupt, probe or gain access to any system, or to collect personal data.`,
          `Try to make the service scan private, internal or local addresses, or this service’s own servers, or to get around the limits and checks (for example by changing DNS answers during a scan).`,
          `Share your account, resell the results as your own testing service, or overload the service.`,
          `Upload or send harmful code, or test the service itself for weaknesses without our written permission. To report a weakness in ${c.product}, email ${c.contactEmail}.`]],
        ["3. Manual verification", [`If an administrator verifies a website by hand, the owner’s name, how consent was given and a reason are recorded and visible in the website’s history.`]],
        ["4. What we do if rules are broken", [`We may pause scans, suspend or close the account and, where the law requires, tell the owner of the affected website or the authorities. All scans are logged with the account, website, address, type, start, end and result.`]],
        ["5. Contact", [`Questions or abuse reports: ${c.contactEmail}.`]],
      ],
    },
  };
}
