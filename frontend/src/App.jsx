import React, { useEffect, useState } from "react";
import { LoaderCircle, ShieldCheck } from "lucide-react";
import LoginPage from "./LoginPage.jsx";
import { ShieldMark } from "./Logo.jsx";
import Console from "./Console.jsx";
import { api } from "./lib/api.js";
import { authRoute } from "./lib/account.js";

function App() {
  const [account, setAccount] = useState(null);
  const [checkingSession, setCheckingSession] = useState(true);
  const [authNotice, setAuthNotice] = useState("");
  // Links from emails: /verify-email?token=... and /reset-password?token=...
  const [link, setLink] = useState(() => authRoute(window.location.pathname, window.location.search));

  const leaveLink = () => {
    if (link.mode) {
      window.history.replaceState(null, "", "/app/");  // the one-time token leaves the address bar
      setLink({ mode: null, token: "" });
    }
  };

  // Restore and verify an existing session when the application opens.
  useEffect(() => {
    let active = true;
    async function restoreSession() {
      if (link.mode || !api.hasSession()) { setCheckingSession(false); return; }
      try {
        const profile = await api.getCurrentAdmin();
        if (active) { api.startSessionTimer(); setAccount(profile); }
      } catch {
        if (active) {
          setAccount(null);
          setAuthNotice(api.hasSession()
            ? "We could not check your session. Make sure the server is running, then sign in again."
            : "Your session has expired. Please sign in again.");
        }
      } finally {
        if (active) setCheckingSession(false);
      }
    }
    restoreSession();
    return () => { active = false; };
  }, []);

  // Return to sign-in if an authenticated API request receives HTTP 401.
  useEffect(() => {
    const expired = () => { setAccount(null); setAuthNotice("Your session has expired. Please sign in again."); };
    window.addEventListener("snwebshield:session-expired", expired);
    return () => window.removeEventListener("snwebshield:session-expired", expired);
  }, []);

  // Re-check expiry after a background tab resumes as well as on the timer.
  useEffect(() => {
    const checkExpiry = () => { if (account && !api.hasSession()) setAccount(null); };
    window.addEventListener("focus", checkExpiry);
    document.addEventListener("visibilitychange", checkExpiry);
    return () => { window.removeEventListener("focus", checkExpiry); document.removeEventListener("visibilitychange", checkExpiry); };
  }, [account]);

  const handleLogin = async credentials => {
    const result = await api.login(credentials);
    setAccount(result.admin || await api.getCurrentAdmin());
    setAuthNotice("");
    leaveLink();
  };

  const handleLogout = () => { api.signOut(); setAccount(null); setAuthNotice(""); };

  if (checkingSession) {
    return <div className="auth-loading"><div className="auth-loading-mark"><ShieldMark size={36} /></div>
      <LoaderCircle className="spin" size={20} /><p>Checking your session…</p></div>;
  }
  if (!account) {
    return <LoginPage onLogin={handleLogin} notice={authNotice}
      initialMode={link.mode || (window.location.hash === "#/signup" ? "signup" : "login")} token={link.token} onLeaveLink={leaveLink} />;
  }
  return <Console account={account} onLogout={handleLogout} />;
}

export default App;
