
import React, { useState } from "react";
import {
  ShieldCheck,
  LockKeyhole,
  Mail,
  Eye,
  EyeOff,
  ArrowRight,
  LoaderCircle,
  AlertCircle,
  CheckCircle2,
} from "lucide-react";

function LoginPage({ onLogin, notice = "" }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError("");

    try {
      await onLogin({
        email: email.trim(),
        password,
      });
    } catch (err) {
      setError(err.message || "Unable to sign in. Please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-shell">
      <section className="auth-visual">
        <div className="auth-visual-brand">
          <div className="auth-brand-mark">
            <ShieldCheck size={25} />
          </div>
          <div>
            <strong>SNWebShield</strong>
            <span>SECURITY CONSOLE</span>
          </div>
        </div>

        <div className="auth-visual-content">
          <div className="auth-chip">
            <span />
            INTERNAL SECURITY PLATFORM
          </div>

          <h1>
            Security begins
            <br />
            with <span>visibility.</span>
          </h1>

          <p>
            Manage client websites, authorisations and security
            assessment operations through one centralised workspace.
          </p>

          <div className="auth-feature-list">
            <div>
              <CheckCircle2 size={17} />
              <span>Centralised client and asset management</span>
            </div>
            <div>
              <CheckCircle2 size={17} />
              <span>Admin-controlled authorisation workflow</span>
            </div>
            <div>
              <CheckCircle2 size={17} />
              <span>Secure, authenticated API access</span>
            </div>
          </div>
        </div>

        <div className="auth-visual-footer">
          <ShieldCheck size={15} />
          <span>Security-first operations by SNIT Cybersecurity</span>
        </div>

        <div className="auth-decoration auth-decoration-one" />
        <div className="auth-decoration auth-decoration-two" />
      </section>

      <section className="auth-panel-wrap">
        <div className="auth-panel">
          <div className="auth-mobile-brand">
            <div className="auth-brand-mark">
              <ShieldCheck size={23} />
            </div>
            <div>
              <strong>SNWebShield</strong>
              <span>SECURITY CONSOLE</span>
            </div>
          </div>

          <div className="auth-heading">
            <div className="auth-heading-icon">
              <LockKeyhole size={22} />
            </div>
            <div className="auth-eyebrow">ADMINISTRATOR ACCESS</div>
            <h2>Welcome back</h2>
            <p>Sign in to access your SNWebShield workspace.</p>
          </div>

          {notice && (
            <div className="auth-notice">
              <AlertCircle size={16} />
              <span>{notice}</span>
            </div>
          )}

          {error && (
            <div className="auth-error" role="alert">
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          <form className="auth-form" onSubmit={handleSubmit}>
            <label className="auth-field">
              <span>Email address</span>
              <div className="auth-input-wrap">
                <Mail size={17} />
                <input
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="admin@company.com"
                  autoComplete="username"
                  maxLength={320}
                  required
                  autoFocus
                />
              </div>
            </label>

            <label className="auth-field">
              <span>Password</span>
              <div className="auth-input-wrap">
                <LockKeyhole size={17} />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                  required
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword((current) => !current)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                </button>
              </div>
            </label>

            <button
              type="submit"
              className="auth-submit"
              disabled={submitting}
            >
              {submitting ? (
                <>
                  <LoaderCircle className="spin" size={17} />
                  Signing in...
                </>
              ) : (
                <>
                  Sign in securely
                  <ArrowRight size={17} />
                </>
              )}
            </button>
          </form>

          <div className="auth-security-note">
            <ShieldCheck size={16} />
            <span>
              Protected administrator access. Your account must be active
              to sign in.
            </span>
          </div>

          <div className="auth-copyright">
            SNWebShield v0.1.0 · SNIT Cybersecurity
          </div>
        </div>
      </section>
    </main>
  );
}

export default LoginPage;
