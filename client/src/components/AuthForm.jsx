export default function AuthForm({ form, onChange, onLogin, onRegister, message }) {
  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="auth-header">
          <div className="logo">🛡️</div>
          <h1>Threat Detection SOC</h1>
          <p>Advanced cybersecurity monitoring platform with real-time threat detection and MITRE ATT&CK mapping.</p>
        </div>

        <div className="auth-form">
          <label htmlFor="username">Username</label>
          <input id="username" name="username" value={form.username} onChange={onChange} placeholder="Enter your username" />

          <label htmlFor="password">Password</label>
          <input id="password" type="password" name="password" value={form.password} onChange={onChange} placeholder="Enter your password" />

          <div className="button-row">
            <button onClick={onLogin} className="primary large">Log In</button>
            <button className="secondary large" onClick={onRegister}>Sign Up</button>
          </div>

          <div className="divider">
            <span>or</span>
          </div>

          <button className="google-btn" onClick={() => alert('Google login not implemented yet')}>
            <img src="https://developers.google.com/identity/images/g-logo.png" alt="Google" />
            Continue with Google
          </button>
        </div>

        {message && <div className="message">{message}</div>}
      </div>
    </div>
  );
}
