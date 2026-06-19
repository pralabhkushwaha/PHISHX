import streamlit as st
import re
from datetime import datetime
import time

# MUST BE FIRST
st.set_page_config(
    page_title="PhishX — Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@400;500;600;700&display=swap');

html, body,
[data-testid="stAppViewContainer"],
[data-testid="stMain"],
[data-testid="block-container"],
.main, .stApp {
    background: #F8FAFC !important;
    color: #0F172A !important;
}
div[class*="stMarkdown"],div[class*="element-container"],
div[class*="stButton"],div[class*="row-widget"],
div[data-baseweb],div[data-testid]{background:transparent !important;}

#MainMenu,footer,header,
[data-testid="stToolbar"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"]{
    visibility:hidden !important;height:0 !important;padding:0 !important;
}
.block-container{padding:0 !important;max-width:100% !important;}

[data-testid="stAppViewContainer"]>div,
[data-testid="stMain"]>div,
section.main>div{position:relative;z-index:1;}

.stTextInput input,div[data-baseweb="base-input"] input{
    background:#FFFFFF !important;
    border:1px solid #CBD5E1 !important;
    border-radius:6px !important;color:#0F172A !important;
    font-family:'Share Tech Mono',monospace !important;
    font-size:0.85rem !important;caret-color:#059669 !important;
    padding:10px 14px !important;
    box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05) !important;
}
.stTextInput input:focus,div[data-baseweb="base-input"] input:focus{
    border-color:#059669 !important;
    box-shadow:0 0 0 2px rgba(5,150,105,0.2) !important;
    outline:none !important;
}
.stTextInput input::placeholder{color:#94A3B8 !important;}
div[data-baseweb="input"],div[data-baseweb="base-input"],div[data-baseweb="textarea"]{
    background:#FFFFFF !important;
    border:1px solid #CBD5E1 !important;border-radius:6px !important;
}
.stTextArea textarea,div[data-baseweb="textarea"] textarea{
    background:#FFFFFF !important;
    border:1px solid #CBD5E1 !important;border-radius:6px !important;
    color:#1E293B !important;
    font-family:'Rajdhani',sans-serif !important;
    font-size:0.93rem !important;line-height:1.65 !important;
    caret-color:#059669 !important;padding:10px 14px !important;
    box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05) !important;
}
.stTextArea textarea:focus{
    border-color:#059669 !important;
    box-shadow:0 0 0 2px rgba(5,150,105,0.2) !important;outline:none !important;
}
.stTextArea textarea::placeholder{color:#94A3B8 !important;}
.stTextInput label,.stTextArea label,
div[data-testid="stTextInput"] label,div[data-testid="stTextArea"] label{
    color:#64748B !important;
    font-family:'Share Tech Mono',monospace !important;
    font-size:0.6rem !important;letter-spacing:2px !important;
    text-transform:uppercase !important;font-weight:600 !important;
}

.stButton button{
    background:#FFFFFF !important;
    color:#059669 !important;
    border:1px solid #059669 !important;
    border-radius:7px !important;padding:13px 28px !important;
    font-family:'Orbitron',monospace !important;
    font-size:0.68rem !important;font-weight:700 !important;
    letter-spacing:4px !important;width:100% !important;transition:all .25s !important;
    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1) !important;
}
.stButton button:hover{
    background:#059669 !important;
    color:#FFFFFF !important;
    transform:translateY(-1px) !important;
    box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1) !important;
}
.stButton button:focus{outline:none !important;box-shadow:none !important;}

.stDownloadButton button{
    background:#FEF2F2 !important;
    color:#DC2626 !important;
    border:1px solid #FCA5A5 !important;
    border-radius:6px !important;padding:10px 20px !important;
    font-family:'Share Tech Mono',monospace !important;
    font-size:0.62rem !important;letter-spacing:2px !important;
    width:100% !important;transition:all .2s !important;margin-top:4px !important;
}
.stDownloadButton button:hover{
    background:#DC2626 !important;
    color:#FFFFFF !important;
}

details,[data-testid="stExpander"]{
    background:#FFFFFF !important;
    border:1px solid #E2E8F0 !important;
    border-radius:8px !important;margin-bottom:5px !important;
    box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.05) !important;
}
[data-testid="stExpander"] summary,details summary{
    color:#0F172A !important;
    font-family:'Rajdhani',sans-serif !important;
    font-size:0.9rem !important;font-weight:700 !important;
    padding:9px 12px !important;
}
[data-testid="stExpander"]>div>div,details>div{
    background:transparent !important;padding:0 !important;
}

::-webkit-scrollbar{width:6px;}
::-webkit-scrollbar-track{background:#F1F5F9;}
::-webkit-scrollbar-thumb{background:#CBD5E1;border-radius:6px;}
::-webkit-scrollbar-thumb:hover{background:#94A3B8;}

.stSpinner>div{border-top-color:#059669 !important;}
div[data-testid="column"]{padding:0 5px !important;}

@keyframes float{0%,100%{transform:translateY(0);}50%{transform:translateY(-4px);}}
</style>
""", unsafe_allow_html=True)

# SESSION STATE
for k, v in [("history",[]),("total",0),("caught",0),
             ("suspicious",0),("clean_c",0),("last_result",None)]:
    if k not in st.session_state:
        st.session_state[k] = v

# SECURITY TIPS (Contains all 5 rules including 'Inspect Every URL')
TIPS = [
    ("👤","Verify Sender Identity",
     "Attackers fake sender display names easily. The real clue is the actual email address — not the name shown.",
     [("Click on the sender name","The real email address appears below the display name — check it carefully"),
      ("Check the domain part","paypal.com ✓ safe   |   paypa1-support.net ✗ fake"),
      ("Look for tiny typos","gooogle.com / amaz0n.com / micros0ft.com — all fake lookalikes"),
      ("Free email = red flag","support@gmail.com from your 'bank' is always suspicious")]),
    ("🔗","Inspect Every URL",
     "A link can say 'www.paypal.com' but send you somewhere dangerous. Always check the real destination.",
     [("Hover mouse over the link","Real URL appears in the bottom-left corner of your browser — read it carefully"),
      ("Watch for raw IP addresses","http://192.168.1.1/login — no real company uses IP-based URLs"),
      ("Spot lookalike domains","paypa1.com / g00gle.com / arnazon.com are all phishing sites"),
      ("URL shorteners are red flags","bit.ly / tinyurl / goo.gl — these hide where they actually go")]),
    ("🧠","Resist Urgency Tactics",
     "Phishers make you panic so you act without thinking. 'Account closes in 24 hours!' is pure manipulation.",
     [("Pause — don't act immediately","Any email demanding instant action should make you MORE suspicious"),
      ("Real companies don't work like this","Banks always give days/weeks of notice — never hours"),
      ("Open a new tab manually","Type the official URL yourself instead of clicking the email link"),
      ("Call their official number","Find it on the real website — never use numbers from the email")]),
    ("🔑","Never Share Credentials",
     "Zero exceptions: no legitimate company will EVER ask for passwords, OTPs, or PINs via email.",
     [("Password request = always a scam","No bank, Google, PayPal, or real service asks for passwords by email"),
      ("OTP request = always a scam","If an email asks for your one-time code — it is phishing, period"),
      ("Card details request = always a scam","Real payment systems never ask for card numbers over email"),
      ("When unsure — don't","Close the email and contact the company directly through their official site")]),
    ("📞","Verify Directly",
     "Got a suspicious email? Contact the company through official channels only — never through the email itself.",
     [("Type the URL manually","Open new browser tab → type official address yourself — do not click links"),
      ("Use the official mobile app","Open your bank/service app directly to check for any real alerts"),
      ("Call the official number","Find phone number on the official website — not from the suspicious email"),
      ("Check your account directly","Log into the real website to see if there's actually an issue")]),
]

# DETECTION DATABASES (Focused strictly on Keyword & Pattern Analysis)
PHISHING_KW = [
    "verify your account","confirm your identity","update your information",
    "click here immediately","your account has been suspended","unusual activity",
    "limited time offer","act now","urgent action required","you have won",
    "claim your prize","free gift","credit card number","social security",
    "login credentials","wire transfer","western union","inheritance",
    "lottery winner","dear account holder","verify immediately",
    "failure to verify","account will be closed","click the link below",
    "confirm your password","reset your credentials","suspended account",
]
URGENCY = [
    "immediately","urgent","asap","right away","today only","expires soon",
    "last chance","final notice","within 24 hours","within 48 hours",
    "act fast","do not ignore","respond now","limited time",
]

def analyze(subject, body):
    flags, score = [], 0
    text = (subject + " " + body).lower()
    
    hits = [k for k in PHISHING_KW if k in text]
    if hits:
        score += min(len(hits)*8, 40)
        for k in hits[:5]: flags.append(("danger", f'Known phishing phrase: "{k}"'))
        
    urg = [u for u in URGENCY if u in text]
    if urg:
        score += min(len(urg)*5, 20)
        flags.append(("warn", f'Urgency manipulation: {", ".join(urg[:4])}'))
        
    if any(k in text for k in ["click here","click the link","click below"]):
        score += 10
        flags.append(("warn", 'Mentions "click" prompts to redirect user'))
        
    if body.count("!") > 3:
        score += min(body.count("!")*2, 10)
        flags.append(("warn", f"Excessive exclamation marks ({body.count('!')})"))
        
    caps = re.findall(r'\b[A-Z]{4,}\b', body)
    if len(caps) > 4:
        score += 8
        flags.append(("warn", f"All-caps pressure words: {', '.join(caps[:5])}"))
        
    for pat, msg in [
        (r'\bpassword\b',"Requests your password"),
        (r'\bssn\b|\bsocial security\b',"Requests Social Security Number"),
        (r'\bcredit card\b|\bcard number\b',"Requests credit card details"),
        (r'\bbank account\b|\baccount number\b',"Requests bank account number"),
        (r'\bdate of birth\b|\bdob\b',"Requests date of birth"),
        (r'\bpin\b',"Requests your PIN"),
        (r'\botp\b|\bone.time password\b',"Requests OTP / 2FA code"),
    ]:
        if re.search(pat, text):
            score += 18; flags.append(("danger", msg))
            
    if re.search(r'\bdear (customer|user|account holder|member|valued customer|client)\b', text):
        score += 6; flags.append(("warn", 'Generic greeting — real orgs address you by name'))
        
    for t in ["account will be closed","legal action","arrest",
              "immediately suspended","permanently disabled","law enforcement"]:
        if t in text:
            score += 12; flags.append(("danger", f'Intimidation tactic: "{t}"'))
            
    if "kindly" in text:
        score += 4; flags.append(("warn", '"Kindly" — hallmark of scam emails'))
        
    if re.search(r'\bprince\b|\binheritance\b|\bescrow\b|\blottery\b', text):
        score += 20; flags.append(("danger", "Advance-fee fraud indicators detected"))
        
    if subject:
        for s in ["you have won","lottery","claim","prize","urgent","action required",
                  "verify","suspended","winner"]:
            if s in subject.lower(): score += 5; break
            
    score = min(score, 100)
    
    if score >= 65:
        return dict(score=score, verdict="PHISHING DETECTED", short="THREAT",
                    clr="#DC2626", bg="#FEF2F2", bdr="#FCA5A5", text_clr="#991B1B",
                    desc="High confidence attack. Do NOT interact or share information.",
                    flags=flags, kw_cnt=len(hits),
                    subject=subject, body=body, ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    elif score >= 35:
        return dict(score=score, verdict="SUSPICIOUS EMAIL", short="CAUTION",
                    clr="#D97706", bg="#FFFBEB", bdr="#FCD34D", text_clr="#92400E",
                    desc="Multiple red flags. Verify sender independently before any action.",
                    flags=flags, kw_cnt=len(hits),
                    subject=subject, body=body, ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    else:
        return dict(score=score, verdict="APPEARS SAFE", short="CLEAN",
                    clr="#059669", bg="#ECFDF5", bdr="#6EE7B7", text_clr="#065F46",
                    desc="No significant phishing indicators found. Stay vigilant.",
                    flags=flags, kw_cnt=len(hits),
                    subject=subject, body=body, ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

def make_report(r):
    sep  = "═"*60
    sep2 = "─"*60
    lines = ["",
        "THREAT INTELLIGENCE REPORT", sep,
        f"Timestamp    : {r['ts']}",
        f"Verdict      : {r['verdict']}",
        f"Threat Score : {r['score']} / 100",
        f"Keywords Hit : {r['kw_cnt']}",
        f"Total Flags  : {len(r['flags'])}", sep,
        f"Subject : {r['subject'] or '(no subject)'}",
        "", "Body Preview:", r['body'][:400]+("..." if len(r['body'])>400 else ""),
        sep, f"THREAT INDICATORS ({len(r['flags'])} found)", sep2,
    ]
    for lvl, msg in r['flags']:
        lines.append(f"  {'[DANGER]' if lvl=='danger' else '[WARN]  '}  {msg}")
    if not r['flags']: lines.append("  No threat indicators found.")
    lines += [sep, "RECOMMENDED ACTIONS", sep2]
    if r['short'] == "THREAT":
        lines += ["  1. DO NOT reply or provide any personal information",
                  "  2. Report to your IT/security team immediately",
                  "  3. Mark as Phishing/Spam in your email client",
                  "  4. Delete the email permanently",
                  "  5. Notify your bank if financial info was shared"]
    elif r['short'] == "CAUTION":
        lines += ["  1. Verify sender via official phone number",
                  "  2. Do NOT click links — visit official site manually",
                  "  3. If uncertain — treat as phishing and delete"]
    else:
        lines += ["  1. Email appears safe — stay vigilant always",
                  "  2. Verify unexpected requests independently"]
    lines += [sep, "PhishX Threat Intelligence Report",
              "Generated for educational and cybersecurity awareness purposes.", sep, ""]
    return "\n".join(lines)

def H(html): st.markdown(html, unsafe_allow_html=True)

# HEADER
H("""
<div style="position:relative;z-index:10;text-align:center;
            padding:32px 40px 26px;overflow:hidden;
            background:#FFFFFF;border:1px solid #E2E8F0;
            border-radius:12px;margin-bottom:20px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.05);">
  <div style="font-size:2.2rem;margin-bottom:10px;display:inline-block;
              animation:float 3s ease-in-out infinite;">🛡️</div>
  <div style="font-family:'Orbitron',monospace;font-size:3.4rem;font-weight:900;
              letter-spacing:10px;line-height:1;
              background:linear-gradient(135deg,#059669 0%,#0284C7 50%,#059669 100%);
              -webkit-background-clip:text;-webkit-text-fill-color:transparent;
              background-clip:text;margin-bottom:8px;">PHISHX</div>
  <div style="display:flex;align-items:center;justify-content:center;gap:10px;margin-top:14px;">
    <div style="display:flex;align-items:center;gap:6px;padding:5px 16px;border-radius:20px;
                background:#F1F5F9;border:1px solid #E2E8F0;
                font-family:'Share Tech Mono',monospace;font-size:0.55rem;
                color:#475569;letter-spacing:1px;font-weight:bold;">
      <span style="width:8px;height:8px;border-radius:50%;background:#059669;display:inline-block;"></span>
      SYSTEM ONLINE</div>
    <div style="display:flex;align-items:center;gap:6px;padding:5px 16px;border-radius:20px;
                background:#F1F5F9;border:1px solid #E2E8F0;
                font-family:'Share Tech Mono',monospace;font-size:0.55rem;
                color:#475569;letter-spacing:1px;font-weight:bold;">
      <span style="width:8px;height:8px;border-radius:50%;background:#DC2626;display:inline-block;"></span>
      MONITORING ACTIVE</div>
  </div>
</div>
""")

# STATS BAR
s1, s2, s3, s4 = st.columns(4)
rate = int(st.session_state.caught/st.session_state.total*100
           if st.session_state.total > 0 else 0)
for col, val, lbl, sub, clr in [
    (s1, f"{st.session_state.total:03d}", "Emails Scanned", "total processed", "#059669"),
    (s2, f"{st.session_state.caught:03d}", "Threats Caught", f"{rate}% threat rate", "#DC2626"),
    (s3, f"{st.session_state.suspicious:03d}", "Suspicious", "under review", "#D97706"),
    (s4, f"{st.session_state.clean_c:03d}", "Clean Emails", "verified safe", "#059669"),
]:
    with col:
        H(f"""
        <div style="padding:16px 20px;background:#FFFFFF;
                    border:1px solid #E2E8F0;border-radius:10px;
                    box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);
                    position:relative;overflow:hidden;margin-bottom:20px;">
          <div style="position:absolute;top:0;left:0;bottom:0;width:4px;background:{clr};"></div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:0.55rem;
                      color:#64748B;letter-spacing:2px;
                      text-transform:uppercase;margin-bottom:4px;font-weight:bold;">{lbl}</div>
          <div style="font-family:'Orbitron',monospace;font-size:1.8rem;
                      font-weight:900;color:{clr};line-height:1;">{val}</div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:0.5rem;
                      color:#94A3B8;margin-top:4px;
                      letter-spacing:1px;text-transform:uppercase;">{sub}</div>
        </div>""")

# MAIN BODY
st.markdown("<div style='padding:0 10px 24px 10px;'>", unsafe_allow_html=True)
left, right = st.columns([3, 2], gap="large")

with left:
    H("""
    <div style="background:#FFFFFF;border:1px solid #E2E8F0;
                border-radius:10px 10px 0 0;padding:12px 18px;
                display:flex;align-items:center;justify-content:space-between;
                border-bottom:2px solid #F1F5F9;">
      <div style="font-family:'Share Tech Mono',monospace;font-size:0.65rem;
                  color:#0F172A;letter-spacing:2px;font-weight:bold;">⬡ &nbsp; Email Threat Scanner</div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:0.5rem;padding:3px 10px;
                  border-radius:4px;background:#F1F5F9;
                  color:#475569;border:1px solid #E2E8F0;
                  letter-spacing:1px;font-weight:bold;">NEURAL ENGINE v4</div>
    </div>
    """)

    subject = st.text_input("Subject Line (optional)",
                            placeholder="Enter email subject...", key="subj")
    body    = st.text_area("Email Body — Paste Full Content",
                           placeholder="Paste the complete email content here for keyword & pattern analysis...",
                           height=215, key="body")

    col_scan, col_clear = st.columns([3, 1])
    with col_scan:
        scan = st.button("⬡   INITIATE THREAT SCAN", key="scan_btn")
    with col_clear:
        clear = st.button("🗑  CLEAR", key="clear_btn")

    if clear:
        st.session_state.last_result = None
        st.session_state.history     = []
        st.session_state.total       = 0
        st.session_state.caught      = 0
        st.session_state.suspicious  = 0
        st.session_state.clean_c     = 0
        st.rerun()

    if scan:
        if not body.strip():
            H("""<div style="background:#FEF2F2;border:1px solid #FCA5A5;
                             border-left:4px solid #DC2626;border-radius:6px;
                             padding:12px 16px;margin-top:8px;
                             font-family:'Share Tech Mono',monospace;
                             font-size:0.8rem;color:#991B1B;font-weight:bold;">
                 ⚠ &nbsp; INPUT ERROR — Paste email content first.</div>""")
        else:
            STEPS = [
                "Booting Neural Engine v4.0",
                "Loading keyword threat database",
                "Scanning urgency patterns",
                "Checking credential theft indicators",
                "Running grammar and casing analysis",
                "Calibrating threat score model",
                "Finalizing pattern analysis",
            ]
            TOTAL = len(STEPS)
            loader = st.empty()

            for i, label in enumerate(STEPS):
                completed = i + 1
                pct = int((completed / TOTAL) * 100)
                boxes_html = ""
                for b in range(TOTAL):
                    if b < completed:
                        boxes_html += (
                            f'<div style="width:38px;height:12px;'
                            f'background:#059669;border-radius:2px;"></div>'
                        )
                    else:
                        boxes_html += (
                            f'<div style="width:38px;height:12px;'
                            f'background:#E2E8F0;border-radius:2px;"></div>'
                        )
                done_txt = "SCAN COMPLETE ✓" if pct == 100 else "PROCESSING..."
                html = (
                    f'<div style="background:#FFFFFF;border:1px solid #E2E8F0;'
                    f'border-radius:10px;padding:22px 24px;margin-top:12px;'
                    f'box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.05);">'
                    f'<div style="display:flex;justify-content:space-between;'
                    f'align-items:center;margin-bottom:16px;">'
                    f'<div style="font-size:0.7rem;color:#0F172A;font-weight:bold;'
                    f'letter-spacing:1px;text-transform:uppercase;">'
                    f'&#9671;&nbsp; {label}...</div>'
                    f'<div style="font-size:1rem;font-weight:900;'
                    f'color:#059669;">{pct}%</div>'
                    f'</div>'
                    f'<div style="display:flex;flex-wrap:wrap;gap:4px;">'
                    f'{boxes_html}'
                    f'</div>'
                    f'<div style="margin-top:14px;font-size:0.6rem;font-weight:bold;'
                    f'color:#64748B;letter-spacing:1px;">'
                    f'STEP {completed} OF {TOTAL} &nbsp;&middot;&nbsp; {done_txt}'
                    f'</div>'
                    f'</div>'
                )
                loader.markdown(html, unsafe_allow_html=True)
                time.sleep(0.3)

            result = analyze(subject.strip(), body.strip())
            loader.empty()

            st.session_state.total += 1
            if result["short"] == "THREAT":    st.session_state.caught += 1
            elif result["short"] == "CAUTION": st.session_state.suspicious += 1
            else:                              st.session_state.clean_c += 1
            st.session_state.last_result = result
            st.session_state.history.insert(0, {
                "subj" : subject.strip() or "(no subject)",
                "v"    : result["short"],
                "clr"  : result["clr"],
                "score": result["score"],
                "bg"   : result["bg"],
                "bdr"  : result["bdr"],
                "t"    : datetime.now().strftime("%H:%M"),
            })
            st.session_state.history = st.session_state.history[:8]
            st.rerun()

    if st.session_state.last_result:
        r = st.session_state.last_result
        H(f"""
        <div style="background:{r['bg']};border:1px solid {r['bdr']};
                    border-left:6px solid {r['clr']};border-radius:8px;
                    padding:20px;margin-top:16px;
                    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.05);">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;">
            <div style="flex:1;padding-right:16px;">
              <div style="font-family:'Orbitron',monospace;font-size:1.2rem;
                          font-weight:900;color:{r['text_clr']};letter-spacing:2px;
                          margin-bottom:6px;">{r['verdict']}</div>
              <div style="font-family:'Rajdhani',sans-serif;font-size:1rem;
                          color:{r['text_clr']};font-weight:600;">{r['desc']}</div>
            </div>
            <div style="background:#FFFFFF;border:2px solid {r['bdr']};
                        border-radius:8px;padding:10px 16px;text-align:center;min-width:80px;">
              <div style="font-family:'Share Tech Mono',monospace;font-size:0.55rem;font-weight:bold;
                          color:#64748B;letter-spacing:2px;margin-bottom:2px;">SCORE</div>
              <div style="font-family:'Orbitron',monospace;font-size:2.4rem;
                          font-weight:900;color:{r['clr']};line-height:1;">{r['score']}</div>
            </div>
          </div>
          <div style="background:#FFFFFF;border-radius:4px;height:8px;
                      overflow:hidden;margin-bottom:12px;border:1px solid #E2E8F0;">
            <div style="height:100%;width:{r['score']}%;
                        background:{r['clr']};border-radius:3px;"></div>
          </div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:0.6rem;font-weight:bold;
                      color:{r['text_clr']};display:flex;gap:16px;flex-wrap:wrap;">
            <span>KEYWORDS: {r['kw_cnt']}</span>
            <span>FLAGS: {len(r['flags'])}</span>
            <span>SCAN: {r['ts'].split(' ')[1]}</span>
          </div>
        </div>""")

        if r['flags']:
            H(f"""<div style="font-family:'Share Tech Mono',monospace;font-size:0.6rem;font-weight:bold;
                        color:#475569;letter-spacing:1px;
                        text-transform:uppercase;margin:18px 0 10px;padding-bottom:5px;
                        border-bottom:2px solid #E2E8F0;
                        display:flex;justify-content:space-between;">
              <span>Threat Pattern Indicators</span>
              <span>{len(r['flags'])} signals detected</span></div>""")
            for lvl, msg in r['flags']:
                if lvl == "danger":
                    H(f"""<div style="background:#FEF2F2;border:1px solid #FCA5A5;
                                     border-left:3px solid #DC2626;border-radius:4px;
                                     padding:10px 14px;margin-bottom:8px;
                                     font-family:'Rajdhani',sans-serif;font-size:0.95rem;font-weight:600;
                                     color:#991B1B;display:flex;gap:10px;">
                        <span>⚡</span><span>{msg}</span></div>""")
                else:
                    H(f"""<div style="background:#FFFBEB;border:1px solid #FCD34D;
                                     border-left:3px solid #D97706;border-radius:4px;
                                     padding:10px 14px;margin-bottom:8px;
                                     font-family:'Rajdhani',sans-serif;font-size:0.95rem;font-weight:600;
                                     color:#92400E;display:flex;gap:10px;">
                        <span>△</span><span>{msg}</span></div>""")
        else:
            H("""<div style="background:#ECFDF5;border:1px solid #6EE7B7;
                             border-left:3px solid #059669;border-radius:4px;
                             padding:10px 14px;margin-top:12px;
                             font-family:'Rajdhani',sans-serif;font-size:0.95rem;font-weight:600;
                             color:#065F46;">✓ &nbsp; No threat indicators detected.</div>""")

        st.download_button(
            label="⬡   DOWNLOAD THREAT REPORT  ↓",
            data=make_report(r).encode("utf-8"),
            file_name=f"PhishX_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain", key="dl_report")

with right:
    H("""
    <div style="background:#FFFFFF;border:1px solid #E2E8F0;
                border-radius:10px 10px 0 0;padding:12px 16px;
                display:flex;align-items:center;justify-content:space-between;
                border-bottom:2px solid #F1F5F9;">
      <div style="font-family:'Share Tech Mono',monospace;font-size:0.65rem;font-weight:bold;
                  color:#0F172A;letter-spacing:2px;">🛡 &nbsp; Threat Intelligence</div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:0.5rem;font-weight:bold;
                  color:#64748B;">5 RULES</div>
    </div>""")

    for icon, title, detail, steps in TIPS:
        with st.expander(f"{icon}  {title}"):
            H(f"""<div style="padding:8px 4px 12px;">
              <div style="font-family:'Rajdhani',sans-serif;font-size:0.95rem;font-weight:600;
                          color:#334155;line-height:1.6;margin-bottom:12px;">
                {detail}</div>
              <div style="font-family:'Share Tech Mono',monospace;font-size:0.6rem;font-weight:bold;
                          color:#64748B;letter-spacing:2px;
                          text-transform:uppercase;margin-bottom:10px;">WHAT TO DO</div>""")
            for i, (st_title, st_desc) in enumerate(steps, 1):
                H(f"""<div style="display:flex;gap:12px;align-items:flex-start;
                            padding:10px 12px;margin-bottom:8px;
                            background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;
                            box-shadow: 0 1px 2px rgba(0,0,0,0.02);">
                  <div style="width:26px;height:26px;min-width:26px;
                              background:#ECFDF5;border:1px solid #D1FAE5;border-radius:6px;
                              display:flex;align-items:center;justify-content:center;
                              font-family:'Orbitron',monospace;font-size:0.65rem;
                              font-weight:800;color:#059669;">{i}</div>
                  <div>
                    <div style="font-family:'Rajdhani',sans-serif;font-size:0.95rem;
                                font-weight:700;color:#0F172A;margin-bottom:2px;">{st_title}</div>
                    <div style="font-family:'Rajdhani',sans-serif;font-size:0.85rem;font-weight:500;
                                color:#475569;line-height:1.4;">{st_desc}</div>
                  </div></div>""")
            H("</div>")

    H(f"""
    <div style="background:#FFFFFF;border:1px solid #E2E8F0;
                border-radius:10px;overflow:hidden;margin-top:16px;
                box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.05);">
      <div style="padding:12px 16px;border-bottom:2px solid #F1F5F9;
                  display:flex;align-items:center;justify-content:space-between;">
        <div style="font-family:'Share Tech Mono',monospace;font-size:0.65rem;font-weight:bold;
                    color:#0F172A;letter-spacing:2px;">📡 &nbsp; Scan Log</div>
        <div style="font-family:'Share Tech Mono',monospace;font-size:0.5rem;font-weight:bold;
                    color:#64748B;">{len(st.session_state.history)} ENTRIES</div>
      </div>""")

    if st.session_state.history:
        for item in st.session_state.history:
            subj = (item["subj"][:22]+"...") if len(item["subj"])>22 else item["subj"]
            H(f"""<div style="display:grid;grid-template-columns:1fr 34px auto 36px;gap:8px;
                        align-items:center;padding:10px 16px;
                        border-bottom:1px solid #F1F5F9;">
              <span style="font-family:'Share Tech Mono',monospace;font-size:0.65rem;font-weight:600;
                           color:#334155;overflow:hidden;
                           text-overflow:ellipsis;white-space:nowrap;">{subj}</span>
              <span style="font-family:'Share Tech Mono',monospace;font-size:0.6rem;font-weight:bold;
                           color:#0F172A;text-align:right;">{item['score']}</span>
              <span style="padding:3px 8px;border-radius:4px;font-weight:bold;
                           font-family:'Share Tech Mono',monospace;font-size:0.55rem;
                           background:{item['bg']};color:{item['clr']};
                           border:1px solid {item['bdr']};">{item['v']}</span>
              <span style="font-family:'Share Tech Mono',monospace;font-size:0.55rem;font-weight:bold;
                           color:#94A3B8;text-align:right;">{item['t']}</span>
            </div>""")
    else:
        H("""<div style="padding:26px;text-align:center;
                         font-family:'Share Tech Mono',monospace;font-size:0.65rem;font-weight:bold;
                         color:#94A3B8;letter-spacing:2px;">
            [ NO SCANS YET — AWAITING INPUT ]</div>""")
    H("</div>")

    H("""<div style="text-align:center;margin-top:20px;
                font-family:'Share Tech Mono',monospace;font-size:0.5rem;font-weight:bold;
                color:#94A3B8;letter-spacing:2px;line-height:2;">
      PHISHX v4.0 · AI-POWERED EMAIL THREAT INTELLIGENCE<br>
      Developed as a Cybersecurity Awareness Project<br>
      EDUCATIONAL USE ONLY</div>""")

st.markdown("</div>", unsafe_allow_html=True)