import Logo from "./Logo.jsx";
import ThemeToggle from "./ThemeToggle.jsx";
import React, { useEffect, useRef, useState } from "react";
import {
  ShieldCheck, LockKeyhole, Mail, Eye, EyeOff, ArrowRight, LoaderCircle, AlertCircle, CheckCircle2, User,
} from "lucide-react";
import { api } from "./lib/api.js";
import { passwordHint } from "./lib/account.js";

const PILLARS = [
  "Monitors your websites and alerts you to changes",
  "Detects open ports, software versions and technologies",
  "Shows what is risky and exactly how to fix it",
];

function PasswordInput({ value, onChange, autoComplete, placeholder = "Enter your password" }) {
  const [show, setShow] = useState(false);
  return (
    <div className="auth-input-wrap">
      <LockKeyhole size={17} />
      <input type={show ? "text" : "password"} value={value} onChange={e => onChange(e.target.value)}
        placeholder={placeholder} autoComplete={autoComplete} required maxLength={128} />
      <button type="button" className="password-toggle" onClick={() => setShow(s => !s)}
        aria-label={show ? "Hide password" : "Show password"}>{show ? <EyeOff size={17} /> : <Eye size={17} />}</button>
    </div>
  );
}

function EmailInput({ value, onChange, autoFocus }) {
  return (
    <div className="auth-input-wrap">
      <Mail size={17} />
      <input type="email" value={value} onChange={e => onChange(e.target.value)} placeholder="you@company.com"
        autoComplete="username" maxLength={320} required autoFocus={autoFocus} />
    </div>
  );
}

function Message({ kind, children }) {
  if (!children) return null;
  return <div className={kind === "error" ? "auth-error" : "auth-notice"} role={kind === "error" ? "alert" : "status"}>
    {kind === "error" ? <AlertCircle size={16} /> : <CheckCircle2 size={16} />}<span>{children}</span></div>;
}

function Submit({ busy, label, busyLabel }) {
  return <button type="submit" className="auth-submit" disabled={busy}>
    {busy ? <><LoaderCircle className="spin" size={17} />{busyLabel}</> : <>{label}<ArrowRight size={17} /></>}
  </button>;
}

// mode: login | signup | check-email | forgot | reset-password | verify-email
export default function LoginPage({ onLogin, notice = "", initialMode = "login", token = "", onLeaveLink }) {
  const [mode, setMode] = useState(initialMode);
  const [email, setEmail] = useState(""), [password, setPassword] = useState(""), [name, setName] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [info, setInfo] = useState(notice);
  const [unverified, setUnverified] = useState(false);
  const verifying = useRef(false);

  const go = next => { setMode(next); setError(""); setInfo(""); setUnverified(false); setPassword(""); if (onLeaveLink) onLeaveLink(); };

  async function attempt(action) {
    setBusy(true); setError(""); setInfo("");
    try { await action(); } catch (e) { setError(e.message || "Something went wrong. Please try again."); return e; }
    finally { setBusy(false); }
    return null;
  }

  // Email links: confirm the address as soon as the page opens.
  useEffect(() => {
    if (mode !== "verify-email" || verifying.current) return;
    verifying.current = true;
    if (!token) { setError("This link is missing its code. Open the link from your email again."); return; }
    attempt(async () => {
      const result = await api.verifyEmail(token);
      setInfo(result.message || "Your email is confirmed. You can sign in now.");
    });
  }, [mode, token]);

  const submitLogin = async e => {
    e.preventDefault();
    const failed = await attempt(() => onLogin({ email: email.trim(), password }));
    if (failed?.code === "email_not_verified") setUnverified(true);
  };
  const submitSignup = async e => {
    e.preventDefault();
    const problems = passwordHint(password, email);
    if (problems.length) { setError("Choose a stronger password: " + problems.join(", ") + "."); return; }
    const failed = await attempt(() => api.signUp({ email: email.trim(), password, full_name: name.trim() }));
    if (!failed) { setMode("check-email"); setPassword(""); }
  };
  const submitForgot = async e => {
    e.preventDefault();
    const failed = await attempt(() => api.forgotPassword(email.trim()));
    if (!failed) setInfo("If an account uses this address, we have sent a link to reset your password. Check your inbox.");
  };
  const submitReset = async e => {
    e.preventDefault();
    const problems = passwordHint(password);
    if (problems.length) { setError("Choose a stronger password: " + problems.join(", ") + "."); return; }
    const failed = await attempt(() => api.resetPassword(token, password));
    if (!failed) { go("login"); setInfo("Your password has been changed. Sign in with your new password."); }
  };
  const resend = () => attempt(async () => {
    await api.resendVerification(email.trim());
    setInfo("If this address is waiting for confirmation, we have sent a new link. Check your inbox.");
  });

  const heading = {
    login: ["Welcome back", "Sign in to see your websites and scans."],
    signup: ["Create your account", "Free plan: up to 5 websites. No card needed."],
    "check-email": ["Check your email", `We sent a confirmation link to ${email || "your address"}. Click it to finish signing up.`],
    forgot: ["Forgot your password?", "Enter your email and we will send you a reset link."],
    "reset-password": ["Choose a new password", "Use at least 12 characters, mixing letters, numbers and symbols."],
    "verify-email": ["Confirming your email", "One moment…"],
  }[mode];

  return (
    <main className="auth-shell">
      <section className="auth-visual">
        <div className="auth-visual-brand"><Logo size={38} caption="WEBSITE SECURITY" /></div>
        <div className="auth-visual-content">
          <div className="auth-chip"><span />MONITORS · DETECTS · VALIDATES · PROTECTS</div>
          <h1>Find the weak spots<br />in your website <span>before others do.</span></h1>
          <p>Add your website, prove you own it in about a minute, and SNwebshield starts checking it automatically.</p>
          <div className="auth-feature-list">
            {PILLARS.map(text => <div key={text}><CheckCircle2 size={17} /><span>{text}</span></div>)}
          </div>
        </div>
        <div className="auth-visual-footer"><ShieldCheck size={15} /><span>We only scan websites you have proved you own.</span></div>
        <div className="auth-decoration auth-decoration-one" /><div className="auth-decoration auth-decoration-two" />
      </section>

      <section className="auth-panel-wrap">
        <div className="auth-panel">
          <div className="auth-panel-top"><div className="auth-mobile-brand"><Logo size={32} caption="WEBSITE SECURITY" /></div><ThemeToggle /></div>
          <div className="auth-heading">
            <div className="auth-heading-icon">{mode === "check-email" ? <Mail size={22} /> : <LockKeyhole size={22} />}</div>
            <h2>{heading[0]}</h2>
            <p>{heading[1]}</p>
          </div>

          <Message kind="info">{info}</Message>
          <Message kind="error">{error}</Message>

          {mode === "login" && <form className="auth-form" onSubmit={submitLogin}>
            <label className="auth-field"><span>Email address</span><EmailInput value={email} onChange={setEmail} autoFocus /></label>
            <label className="auth-field"><span>Password</span><PasswordInput value={password} onChange={setPassword} autoComplete="current-password" /></label>
            <Submit busy={busy} label="Sign in" busyLabel="Signing in…" />
            {unverified && <button type="button" className="auth-link" onClick={resend} disabled={busy}>Send me a new confirmation link</button>}
            <div className="auth-switch">
              <button type="button" className="auth-link" onClick={() => go("forgot")}>Forgot password?</button>
              <span>New here? <button type="button" className="auth-link" onClick={() => go("signup")}>Create an account</button></span>
            </div>
          </form>}

          {mode === "signup" && <form className="auth-form" onSubmit={submitSignup}>
            <label className="auth-field"><span>Your name (optional)</span>
              <div className="auth-input-wrap"><User size={17} /><input value={name} onChange={e => setName(e.target.value)} placeholder="Your name" maxLength={150} autoComplete="name" /></div></label>
            <label className="auth-field"><span>Email address</span><EmailInput value={email} onChange={setEmail} autoFocus /></label>
            <label className="auth-field"><span>Password</span><PasswordInput value={password} onChange={setPassword} autoComplete="new-password" placeholder="At least 12 characters" /></label>
            <Submit busy={busy} label="Create account" busyLabel="Creating account…" />
            <div className="auth-switch"><span>Already have an account? <button type="button" className="auth-link" onClick={() => go("login")}>Sign in</button></span></div>
          </form>}

          {mode === "check-email" && <div className="auth-form">
            <button type="button" className="auth-submit" onClick={resend} disabled={busy}>Send the link again</button>
            <div className="auth-switch"><span>Confirmed already? <button type="button" className="auth-link" onClick={() => go("login")}>Sign in</button></span></div>
          </div>}

          {mode === "forgot" && <form className="auth-form" onSubmit={submitForgot}>
            <label className="auth-field"><span>Email address</span><EmailInput value={email} onChange={setEmail} autoFocus /></label>
            <Submit busy={busy} label="Send reset link" busyLabel="Sending…" />
            <div className="auth-switch"><button type="button" className="auth-link" onClick={() => go("login")}>Back to sign in</button></div>
          </form>}

          {mode === "reset-password" && <form className="auth-form" onSubmit={submitReset}>
            <label className="auth-field"><span>New password</span><PasswordInput value={password} onChange={setPassword} autoComplete="new-password" placeholder="At least 12 characters" /></label>
            <Submit busy={busy} label="Save new password" busyLabel="Saving…" />
            <div className="auth-switch"><button type="button" className="auth-link" onClick={() => go("forgot")}>Link expired? Get a new one</button></div>
          </form>}

          {mode === "verify-email" && <div className="auth-form">
            {busy && <p className="auth-progress"><LoaderCircle className="spin" size={17} /> Confirming…</p>}
            {!busy && <button type="button" className="auth-submit" onClick={() => go("login")}>Go to sign in <ArrowRight size={17} /></button>}
          </div>}

          <div className="auth-copyright">SNwebshield · MONITORS. DETECTS. VALIDATES. PROTECTS.</div>
        </div>
      </section>
    </main>
  );
}
