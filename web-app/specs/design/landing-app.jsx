/* Landing — AI Agent Runtime Protection (strict Carbon) */
const { useState, useEffect, useRef } = React;
/* ---------- Carbon icons (inline, 16/20 px, currentColor, Carbon grid) ---------- */
const I = {
  chevronRight: (s=16) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M6 4l4 4-4 4-.7-.7L8.6 8 5.3 4.7z"/>
    </svg>
  ),
  arrowRight: (s=16) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M11.3 8 7.1 3.8l.7-.7L12.7 8l-4.9 4.9-.7-.7z"/>
      <path d="M3 7.5h9v1H3z"/>
    </svg>
  ),
  send: (s=16) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M14.5 1.5 1 6.5l5 2 2 5z"/>
    </svg>
  ),
  close: (s=16) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M12 4.7 11.3 4 8 7.3 4.7 4 4 4.7 7.3 8 4 11.3l.7.7L8 8.7l3.3 3.3.7-.7L8.7 8z"/>
    </svg>
  ),
  user: (s=16) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 8a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0-5a2 2 0 1 0 0 4 2 2 0 0 0 0-4z"/>
      <path d="M14 14H2v-1.5C2 10.6 4.7 9 8 9s6 1.6 6 3.5z"/>
    </svg>
  ),
  agent: (s=16) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 1 2 4v4c0 3.5 2.5 6.6 6 7 3.5-.4 6-3.5 6-7V4L8 1zm0 1.1L13 4.6V8c0 2.9-2 5.4-5 5.9-3-.5-5-3-5-5.9V4.6l5-2.5z"/>
      <path d="M7 9.3 5.7 8l-.7.7L7 10.7l4-4-.7-.7z"/>
    </svg>
  ),
};

/* ---------- IBM mark ---------- */
function IBMMark({ fill = "#0f62fe", width = 40 }) {
  return (
    <svg viewBox="0 0 120 48" width={width} height={width * 48/120} aria-label="IBM">
      <g fill={fill}>
        {[0,8,16,24,32,40].map(y => <rect key={y} y={y} width="120" height="4"/>)}
      </g>
      <g fill="transparent">
        <rect x="4" y="16" width="8" height="4"/><rect x="20" y="16" width="8" height="4"/>
        <rect x="4" y="32" width="8" height="4"/><rect x="20" y="32" width="8" height="4"/>
        <rect x="40" y="16" width="24" height="4"/><rect x="40" y="32" width="24" height="4"/>
        <rect x="76" y="16" width="8" height="4"/><rect x="92" y="16" width="4" height="4"/>
        <rect x="104" y="16" width="8" height="4"/><rect x="76" y="32" width="40" height="4"/>
      </g>
    </svg>
  );
}

/* ---------- UI Shell Header ---------- */
function Header({ user, theme, onTheme, onLogout }) {
  return (
    <header className="cds--header" role="banner">
      <div className="cds--header__left">
        <div className="cds--header__brand">
          <IBMMark fill="#ffffff" width={32}/>
          <span className="cds--header__name">
            <span className="cds--header__product">AI Runtime Security</span>
          </span>
        </div>
        <nav className="cds--header__nav" aria-label="Primary">
          <a className="is-active" href="#">Chat</a>
        </nav>
      </div>
      <div className="cds--header__right">
        <div className="cds--header__user">
          <span className="cds--header__avatar" aria-hidden="true">{I.user(16)}</span>
          <span className="cds--header__username">{user}</span>
        </div>
        <div className="cds--select">
          <select value={theme} onChange={(e) => onTheme(e.target.value)} aria-label="Theme">
            <option value="white">White</option>
            <option value="g100">Dark</option>
          </select>
        </div>
        <button className="cds--btn cds--btn--secondary cds--btn--sm" onClick={onLogout}>
          Log out
        </button>
      </div>
    </header>
  );
}

/* ---------- Hero ---------- */
function Hero({ user, msgCount, onStart }) {
  return (
    <section className="hero">
      <div className="cds--eyebrow">Workspace</div>
      <h1 className="cds--heading-05">Secure conversations<br/>for your AI runtime.</h1>
      <p className="cds--body-02">
        Welcome, {user}. Launch a governed conversation, inspect the delegated identity,
        and keep the agent workspace anchored in one focused control surface.
      </p>
      <button className="cds--btn cds--btn--primary cds--btn--fluid" onClick={onStart}>
        <span>Start chatting</span>
        <span className="cds--btn__icon">{I.arrowRight(16)}</span>
      </button>

      <div className="cds--tile hero-tile">
        <div className="cds--eyebrow">Conversation</div>
        <div className="cds--heading-04 tile-count">{msgCount} message{msgCount === 1 ? '' : 's'}</div>
        <p className="cds--helper">History stays in-session for a continuous operator flow.</p>
      </div>
    </section>
  );
}

/* ---------- Chat ---------- */
function ChatBubble({ role, text }) {
  const icon = role === 'user' ? I.user(16) : role === 'agent' ? I.agent(16) : null;
  const label = role === 'user' ? 'You' : role === 'agent' ? 'Agent' : 'System';
  return (
    <div className={`msg msg--${role}`}>
      <div className="msg__meta">
        <span className="msg__icon" aria-hidden="true">{icon}</span>
        <span className="msg__label">{label}</span>
      </div>
      <div className="msg__text">{text}</div>
    </div>
  );
}

function Chat({ messages, typing }) {

  const customAudience = process.env.CUSTOM_AUDIENCE || 'Your helpful';
  const productTitle = `${customAudience} AI assistant`;

  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [messages, typing]);
  return (
    <section className="chat" aria-label="Conversation">
      <div className="chat__head">
        <div className="cds--eyebrow">Session</div>
        <div className="cds--heading-02">{productTitle}</div>
      </div>
      <div className="chat__log" ref={ref}>
        {messages.map((m, i) => <ChatBubble key={i} role={m.role} text={m.text}/>)}
        {typing && (
          <div className="msg msg--agent">
            <div className="msg__meta">
              <span className="msg__icon">{I.agent(16)}</span>
              <span className="msg__label">Agent</span>
            </div>
            <div className="msg__text">
              <span className="typing"><span/><span/><span/></span>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

/* ---------- Token Accordion ---------- */
const TOKENS = [
  {
    id: 'subject', title: 'Subject token', subtitle: 'access_token · Keycloak',
    fields: [
      ['iss',  'http://localhost:8081/realms/demo'],
      ['sub',  'pravi@ibm.com'],
      ['aud',  'ai-runtime-ui'],
      ['amr',  'mfa, pwd'],
      ['iat',  '2026-04-24T11:31:02Z'],
      ['exp',  '2026-04-24T12:31:02Z'],
    ],
  },
  {
    id: 'actor', title: 'Agent — actor token', subtitle: 'act.sub · delegated',
    fields: [
      ['iss',     'https://verify.ibm.com/oidc'],
      ['client',  'watsonx-agent-runtime'],
      ['scope',   'chat.read chat.write tools.invoke'],
      ['act.sub', 'agent:runtime/abe4-91c2'],
      ['act.typ', 'AgentActor/v1'],
    ],
  },
  {
    id: 'obo', title: 'Agent — OBO token', subtitle: 'on-behalf-of exchange',
    fields: [
      ['iss',       'https://verify.ibm.com/oidc'],
      ['sub',       'pravi@ibm.com'],
      ['act.sub',   'agent:runtime/abe4-91c2'],
      ['scope',     'tools.search tools.retrieve'],
      ['bound_jkt', 'b3eW…f9Lk'],
      ['exp',       '2026-04-24T11:46:02Z'],
    ],
  },
];

function Accordion() {
  const [openId, setOpenId] = useState('subject');
  return (
    <aside className="inspector" aria-label="Identity inspector">
      <div className="cds--eyebrow">Identity inspector</div>
      <h2 className="cds--heading-03">Token context</h2>
      <p className="cds--helper inspector__sub">
        Inspect the subject token and the delegated agent tokens without leaving the workspace.
      </p>
      <ul className="cds--accordion">
        {TOKENS.map(t => {
          const open = openId === t.id;
          return (
            <li key={t.id} className={`cds--accordion__item ${open ? 'is-open' : ''}`}>
              <button
                className="cds--accordion__heading"
                onClick={() => setOpenId(open ? null : t.id)}
                aria-expanded={open}
              >
                <span className={`cds--accordion__caret ${open ? 'is-open' : ''}`}>{I.chevronRight(16)}</span>
                <span className="cds--accordion__title">{t.title}</span>
              </button>
              <div className="cds--accordion__content" style={{ maxHeight: open ? 320 : 0 }}>
                <div className="cds--accordion__inner">
                  <div className="cds--accordion__subtitle">{t.subtitle}</div>
                  <dl className="claims">
                    {t.fields.map(([k, v]) => (
                      <React.Fragment key={k}>
                        <dt>{k}</dt><dd>{v}</dd>
                      </React.Fragment>
                    ))}
                  </dl>
                </div>
              </div>
            </li>
          );
        })}
      </ul>
    </aside>
  );
}

/* ---------- Composer ---------- */
function Composer({ value, onChange, onSend, onClear, disabled }) {
  const max = 1000;
  return (
    <section className="composer" aria-label="Message composer">
      <label className="cds--label" htmlFor="msg">Message your AI agent</label>
      <textarea
        id="msg"
        className="cds--textarea"
        placeholder="Type a message…"
        value={value}
        onChange={(e) => onChange(e.target.value.slice(0, max))}
        onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSend(); } }}
        rows={3}
      />
      <div className="cds--helper-row">
        <span className="cds--helper">Press Enter to send, Shift+Enter for a new line.</span>
        <span className="cds--helper">{value.length}/{max}</span>
      </div>
      <div className="composer__actions">
        <button className="cds--btn cds--btn--tertiary cds--btn--fluid" onClick={onClear}>
          <span>Clear conversation</span>
          <span className="cds--btn__icon">{I.close(16)}</span>
        </button>
        <button className="cds--btn cds--btn--primary cds--btn--fluid" onClick={onSend} disabled={disabled}>
          <span>Send</span>
          <span className="cds--btn__icon">{I.send(16)}</span>
        </button>
      </div>
    </section>
  );
}

/* ---------- App ---------- */
function App() {
  const [theme, setTheme] = useState('white');
  const [messages, setMessages] = useState([
    { role: 'user',  text: "Hey, what's up?" },
    { role: 'agent', text: 'Hello. The runtime is live and your session is governed by Keycloak. What do you want to work on?' },
  ]);
  const [input, setInput] = useState('');
  const [typing, setTyping] = useState(false);

  useEffect(() => {
    document.documentElement.setAttribute('data-carbon-theme', theme);
  }, [theme]);

  const user = 'pravi';

  function reply(text) {
    const t = text.toLowerCase();
    if (t.includes('token') || t.includes('identity')) {
      return 'Open the identity inspector on the right to see your subject token alongside the agent actor and OBO tokens.';
    }
    if (t.includes('help')) {
      return 'I can answer questions, invoke governed tools, and trace every action back to the delegated token that authorized it.';
    }
    if (t.match(/^(hi|hey|hello)\b/)) {
      return 'Hello. The runtime is ready — what do you want to work on?';
    }
    return `Routing "${text.slice(0, 60)}${text.length > 60 ? '…' : ''}" through the governed toolchain.`;
  }

  function send() {
    const text = input.trim();
    if (!text) return;
    setMessages(prev => [...prev, { role: 'user', text }]);
    setInput('');
    setTyping(true);
    const r = reply(text);
    setTimeout(() => {
      setTyping(false);
      setMessages(prev => [...prev, { role: 'agent', text: r }]);
    }, 800);
  }
  function clear() { setMessages([]); }
  function start() { const el = document.getElementById('msg'); if (el) el.focus(); }
  function logout() { window.location.href = 'Login.html'; }

  return (
    <div className="app">
      <Header user={user} theme={theme} onTheme={setTheme} onLogout={logout}/>
      <div className="grid">
        <Hero user={user} msgCount={messages.length} onStart={start}/>
        <Chat messages={messages} typing={typing}/>
        <Accordion/>
      </div>
      <div className="composer-wrap">
        <Composer
          value={input} onChange={setInput}
          onSend={send} onClear={clear}
          disabled={!input.trim() || typing}
        />
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
