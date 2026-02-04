import gradio as gr
from mlx_lm import load, generate
import PyPDF2
import docx
from PIL import Image
import easyocr
import numpy as np
import re
import base64
import requests
from urllib.parse import unquote
from email import policy
from email.parser import BytesParser
import math
from collections import Counter
import os

# ============================================================
# startup
# ============================================================

print("Loading Llama 3.1 8B...")
model, tokenizer = load("./llama-mlx-8bit")
print("Loading OCR engine...")
reader = easyocr.Reader(['en'])
print("Threat Detection System Online!\n")

# global state - tracks currently loaded document
current_document = ""
analysis_report = ""

# ============================================================
# URL extraction - pulls links from plain text,
# encoded text, and hidden/obfuscated URLs
# ============================================================

def extract_urls(text):
    # decode URL encoding first - catches %22__https://... patterns
    decoded = unquote(text)

    # try decoding any base64 chunks found in the text
    b64_chunks = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', text)
    for chunk in b64_chunks:
        try:
            decoded += " " + base64.b64decode(chunk).decode('utf-8', errors='ignore')
        except:
            pass

    pattern = r'https?://[^\s<>"\')\]}]*[^\s<>"\')\]}.,:;!?]'

    # search both decoded and original text
    urls = re.findall(pattern, decoded)
    urls.extend(re.findall(pattern, text))

    # remove duplicates
    return list(set(urls))

# helper - calculates string randomness
# higher entropy = more random
# readable words score low, gibberish like "tqbsdnn" scores high
def calculate_entropy(s):
    if not s:
        return 0
    counter = Counter(s.lower())
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())

# ============================================================
# domain analysis - typosquatting, bad TLDs, IP domains, etc.
# ============================================================

def analyze_domain(url):
    results = []
    try:
        domain = re.search(r'://([^/]+)', url).group(1).lower()

        # typosquatting check - common brands attackers impersonate
        known_brands = {
            'paypal': ['paypa1', 'paypai', 'paypal1', 'paypall'],
            'amazon': ['arnazon', 'amazom', 'amaz0n'],
            'microsoft': ['micros0ft', 'microsft', 'mlcrosoft'],
            'google': ['g00gle', 'googie', 'gooogle'],
            'apple': ['app1e', 'appie', 'appl3'],
            'facebook': ['faceb00k', 'facebok'],
            'instagram': ['instgram', 'instagran'],
            'netflix': ['netfl1x', 'netfllx'],
            'bank': ['b4nk', 'banck'],
            'support': ['supp0rt', 'supportt']
        }

        for brand, fakes in known_brands.items():
            if any(f in domain for f in fakes):
                results.append(f"🚨 CRITICAL: Typosquatting detected — mimics {brand.upper()}")

        # check for HTTPS
        if not url.startswith('https://'):
            results.append("⚠️ WARNING: No HTTPS encryption")

        # suspicious TLDs commonly used by scammers
        bad_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link']
        if any(domain.endswith(t) for t in bad_tlds):
            results.append("⚠️ SUSPICIOUS: High-risk domain extension")

        # raw IP address instead of domain name
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            results.append("🚨 CRITICAL: Raw IP address — no domain name")

        # excessive subdomains indicate obfuscation
        if domain.count('.') > 3:
            results.append("⚠️ WARNING: Excessive subdomains (obfuscation attempt)")

        # known redirect/tracking domains
        redirect_domains = ['mandrillapp.com', 'bit.ly', 'tinyurl.com', 'ow.ly', 'is.gd', 't.co']
        if any(rd in domain for rd in redirect_domains):
            results.append("⚠️ INFO: Redirect/tracking URL detected — hides the real destination")

        # random subdomain detection
        # legitimate subdomains are readable (www, mail, app)
        # phishing subdomains are gibberish (tqbsdnn, xk7mq2)
        parts = domain.split('.')
        if len(parts) > 2:
            subdomain = parts[0]
            legit_subdomains = ['www', 'mail', 'app', 'blog', 'api', 'support',
                                'admin', 'dev', 'staging', 'test', 'cdn', 'static',
                                'media', 'login', 'secure', 'account', 'webmail',
                                'smtp', 'pop', 'imap', 'ftp', 'ns1', 'ns2']
            if subdomain not in legit_subdomains and len(subdomain) > 3:
                vowels = sum(1 for c in subdomain if c in 'aeiou')
                if vowels == 0:
                    results.append("🚨 HIGH: Random subdomain detected — no vowels, auto-generated")
                elif calculate_entropy(subdomain) > 3.2 and len(subdomain) > 5:
                    results.append("⚠️ SUSPICIOUS: Subdomain looks randomly generated")

        # victim-tracking token detection
        # phishers embed unique IDs in URLs to track individual targets
        # legitimate paths are short (/login, /payments)
        path_match = re.search(r'://[^/]+(/.+)', url)
        if path_match:
            path = path_match.group(1)
            segments = [s for s in path.split('/') if s]
            for seg in segments:
                if len(seg) > 20:
                    has_upper = bool(re.search(r'[A-Z]', seg))
                    has_lower = bool(re.search(r'[a-z]', seg))
                    has_digits = bool(re.search(r'[0-9]', seg))
                    mix_count = sum([has_upper, has_lower, has_digits])
                    if mix_count >= 2 and calculate_entropy(seg) > 3.5:
                        results.append("🚨 HIGH: Victim-tracking token in path — unique ID per target")
                        break

        return results if results else ["✅ Domain checks passed"]

    except Exception as e:
        return [f"❌ Domain analysis error: {str(e)}"]

# ============================================================
# VirusTotal - queries 70+ antivirus engines
# ============================================================

def check_virustotal(url):
    # hardcoded API key for local development
    API_KEY = "YOUR_API_KEY"

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=5
        )

        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)

            if malicious > 0:
                return [f"🚨 THREAT DETECTED: {malicious} vendors flagged as malicious"]
            if suspicious > 0:
                return [f"⚠️ SUSPICIOUS: {suspicious} vendors flagged as suspicious"]
            return ["✅ VirusTotal: Clean"]

        return ["ℹ️ VirusTotal: URL not in database yet"]

    except Exception as e:
        return [f"⚠️ VirusTotal check failed: {str(e)}"]

# ============================================================
# email header analysis - SPF, DKIM, DMARC, Reply-To checks
# ============================================================

def analyze_email_headers(file):
    try:
        with open(file.name, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        results = []

        # SPF verification
        spf = msg.get('Received-SPF', '')
        if 'pass' in spf.lower():
            results.append("✅ SPF: PASS")
        elif 'fail' in spf.lower():
            results.append("🚨 SPF: FAIL — sender not authorized")
        else:
            results.append("⚠️ SPF: Not found")

        # DKIM and DMARC are in Authentication-Results header
        auth = msg.get('Authentication-Results', '')

        if 'dkim=pass' in auth.lower():
            results.append("✅ DKIM: PASS")
        elif 'dkim=fail' in auth.lower():
            results.append("🚨 DKIM: FAIL — signature invalid")
        else:
            results.append("⚠️ DKIM: Not found")

        if 'dmarc=pass' in auth.lower():
            results.append("✅ DMARC: PASS")
        elif 'dmarc=fail' in auth.lower():
            results.append("🚨 DMARC: FAIL — domain not authenticated")
        else:
            results.append("⚠️ DMARC: Not found")

        # extract sender information
        from_addr = msg.get('From', 'Unknown')
        results.append(f"📧 From: {from_addr}")

        # Reply-To mismatch is a major red flag
        reply_to = msg.get('Reply-To', None)
        if reply_to and reply_to != from_addr:
            results.append(f"🚨 Reply-To MISMATCH: {reply_to}")

        return results

    except Exception as e:
        return [f"Header analysis failed: {str(e)}"]

# ============================================================
# core scanning - runs all security checks on text
# ============================================================

def run_security_analysis(text):
    global analysis_report

    report = ["⬡ THREAT ANALYSIS INITIATED", "=" * 50, ""]

    urls = extract_urls(text)
    if urls:
        report.append(f"⬡ DETECTED {len(urls)} URL(s):\n")
        for url in urls[:5]:
            report.append(f"🔗 {url}")
            for r in analyze_domain(url):
                report.append(f"   {r}")
            for r in check_virustotal(url):
                report.append(f"   {r}")
            report.append("")

        if len(urls) > 5:
            report.append(f"⚠️ +{len(urls) - 5} more URLs not shown")
    else:
        report.append("⬡ NO URLS DETECTED IN SAMPLE")

    analysis_report = "\n".join(report)
    return analysis_report

# ============================================================
# scans URLs pasted directly into chat
# ============================================================

def scan_chat_input(text):
    urls = extract_urls(text)
    if not urls:
        return ""

    scan = "⬡ URL ANALYSIS:\n"
    for url in urls[:5]:
        scan += f"\n⬡ TARGET: {url}\n"
        for r in analyze_domain(url):
            scan += f"   {r}\n"
        for r in check_virustotal(url):
            scan += f"   {r}\n"
    return scan

# ============================================================
# file handling - extracts text from uploaded files
# ============================================================

def extract_text_from_file(file):
    global analysis_report

    if not file:
        return ""

    filename = file.name.lower()

    try:
        # email files - check headers and scan body for URLs
        if filename.endswith('.eml'):
            headers = analyze_email_headers(file)
            analysis_report = "⬡ EMAIL AUTHENTICATION ANALYSIS:\n" + "\n".join(headers) + "\n\n"

            with open(file.name, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
                body = msg.get_body(preferencelist=('plain', 'html'))
                text = body.get_content() if body else ""

            # scan email body for hidden links
            run_security_analysis(text)
            # combine header and body results
            analysis_report = "⬡ EMAIL AUTHENTICATION ANALYSIS:\n" + "\n".join(headers) + "\n\n" + analysis_report
            return text

        # screenshots - use OCR to extract text
        if filename.endswith(('.png', '.jpg', '.jpeg', '.webp', '.heic')):
            image = Image.open(file)
            text = "\n".join(reader.readtext(np.array(image), detail=0))
            run_security_analysis(text)
            return text

        # PDF documents
        if filename.endswith('.pdf'):
            pdf = PyPDF2.PdfReader(file)
            text = "\n".join([page.extract_text() for page in pdf.pages])
            run_security_analysis(text)
            return text

        # Word documents
        if filename.endswith('.docx'):
            doc = docx.Document(file)
            text = "\n".join([p.text for p in doc.paragraphs])
            run_security_analysis(text)
            return text

        # plain text files
        if filename.endswith('.txt'):
            text = file.read().decode('utf-8')
            run_security_analysis(text)
            return text

        return "Unsupported file type"

    except Exception as e:
        return f"Error: {str(e)}"

def upload_document(file):
    global current_document

    if not file:
        current_document = ""
        return "⬡ SYSTEM IDLE - AWAITING INPUT"

    text = extract_text_from_file(file)
    current_document = text
    words = len(text.split())
    preview = text[:400] + "..." if len(text) > 400 else text

    status = f"⬡ SAMPLE EXTRACTED — {words} WORDS PROCESSED\n\n"
    if analysis_report:
        status += analysis_report + "\n\n"
    status += f"PREVIEW:\n{preview}"

    return status

def clear_document():
    global current_document, analysis_report
    current_document = ""
    analysis_report = ""
    return None, "⬡ SYSTEM IDLE - AWAITING INPUT"

# ============================================================
# chat function - Python does scanning, Llama explains results
# this architecture prevents Llama from refusing to analyze URLs
# ============================================================

def chat(message, history):
    # step 1: Python performs actual security scanning
    chat_scan = scan_chat_input(message)

    # step 2: build prompt for Llama (explanation only, not analysis)
    prompt = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n"
    prompt += ("You are a security report writer. You are given automated scan results "
               "from a threat detection system. Explain the findings in plain English and "
               "give an overall risk rating: LOW, MEDIUM, HIGH, or CRITICAL.<|eot_id|>")

    if chat_scan:
        # have scan results from pasted URL - explain them
        prompt += f"<|start_header_id|>user<|end_header_id|>\nExplain these scan results:\n\n{chat_scan}<|eot_id|>"

    elif current_document and analysis_report:
        # file loaded and scanned - explain file analysis
        prompt += (f"<|start_header_id|>user<|end_header_id|>\n"
                   f"Scan results:\n{analysis_report}\n\n"
                   f"Content:\n{current_document[:3000]}\n\n"
                   f"User question: {message}<|eot_id|>")

    elif current_document:
        # file loaded but not yet scanned
        prompt += (f"<|start_header_id|>user<|end_header_id|>\n"
                   f"Content:\n{current_document[:3000]}\n\n{message}<|eot_id|>")

    else:
        # general chat without files
        prompt += f"<|start_header_id|>user<|end_header_id|>\n{message}<|eot_id|>"

    prompt += "<|start_header_id|>assistant<|end_header_id|>\n"

    # step 3: get Llama's explanation
    llama_response = generate(model, tokenizer, prompt=prompt, max_tokens=1000)

    # step 4: return scan results plus explanation
    # scan results always display even if Llama fails
    if chat_scan:
        return f"{chat_scan}\n---\n\n{llama_response}"

    return llama_response

# ============================================================
# UI styling
# ============================================================

css = """
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&display=swap');

* { 
    font-family: 'Rajdhani', sans-serif !important;
}

.gradio-container {
    background: #0a0a0a !important;
    background-image: 
        linear-gradient(0deg, transparent 24%, rgba(255, 255, 255, .02) 25%, rgba(255, 255, 255, .02) 26%, transparent 27%, transparent 74%, rgba(255, 255, 255, .02) 75%, rgba(255, 255, 255, .02) 76%, transparent 77%, transparent),
        linear-gradient(90deg, transparent 24%, rgba(255, 255, 255, .02) 25%, rgba(255, 255, 255, .02) 26%, transparent 27%, transparent 74%, rgba(255, 255, 255, .02) 75%, rgba(255, 255, 255, .02) 76%, transparent 77%, transparent);
    background-size: 50px 50px;
    max-width: 100% !important;
}

#chatbot {
    background: #000 !important;
    border: 3px solid #fff !important;
    box-shadow: 0 0 30px rgba(255, 255, 255, 0.1), inset 0 0 20px rgba(255, 255, 255, 0.03) !important;
}

textarea, input {
    background: #000 !important;
    border: 2px solid #fff !important;
    color: #fff !important;
    font-family: 'Share Tech Mono', monospace !important;
}

textarea:focus, input:focus {
    box-shadow: 0 0 10px rgba(255, 255, 255, 0.3) !important;
}

button {
    background: #000 !important;
    border: 2px solid #fff !important;
    color: #fff !important;
    font-weight: 700 !important;
    letter-spacing: 3px !important;
    text-transform: uppercase !important;
    transition: all 0.2s !important;
}

button:hover {
    background: #fff !important;
    color: #000 !important;
    box-shadow: 0 0 20px rgba(255, 255, 255, 0.5) !important;
}

h1, h2, h3 { 
    color: #fff !important; 
    text-transform: uppercase !important;
    font-weight: 700 !important;
    letter-spacing: 4px !important;
}

#doc-status {
    background: #000 !important;
    border: 2px solid #fff !important;
    color: #fff !important;
    font-family: 'Share Tech Mono', monospace !important;
    box-shadow: inset 0 0 10px rgba(255, 255, 255, 0.05) !important;
}

.contain {
    background: #000 !important;
}

/* threat level color coding */
#chatbot .message {
    font-family: 'Share Tech Mono', monospace !important;
}

@media (max-width: 768px) {
    h1 { font-size: 2em !important; }
    button { width: 100% !important; margin: 5px 0 !important; }
    textarea, input { font-size: 16px !important; }
    #chatbot { height: 400px !important; }
}
"""

# ============================================================
# application interface
# ============================================================

with gr.Blocks(title="🛡️ PHISHING THREAT ANALYZER") as demo:

    gr.HTML("""
        <div style='text-align:center; padding:40px; background:#000; border-bottom:3px solid #fff;'>
            <h1 style='font-size:3.5em; color:#fff; margin:10px 0; letter-spacing:8px; text-shadow: 0 0 20px rgba(255,255,255,0.3);'>⬡ PHISHING THREAT ANALYZER</h1>
            <p style='color:#fff; font-size:1.3em; letter-spacing:3px; margin:15px 0;'>ADVANCED THREAT DETECTION SYSTEM</p>
            <p style='color:#aaa; font-size:0.95em; letter-spacing:2px; font-family:Share Tech Mono, monospace;'>LLAMA 3.1 8B • OCR ENGINE • URL ANALYSIS • VIRUSTOTAL • EMAIL AUTH</p>
            <div style='margin-top:20px; padding:10px; border:1px solid #333; display:inline-block;'>
                <p style='color:#fff; font-size:0.8em; margin:0; font-family:Share Tech Mono, monospace;'>SYSTEM STATUS: <span style='color:#0f0;'>● ONLINE</span></p>
            </div>
        </div>
    """)

    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown("### ⬡ UPLOAD THREAT SAMPLE")
            file_upload = gr.File(
                label="⬡ DROP SAMPLE FILE",
                file_types=['.pdf', '.docx', '.txt', '.png', '.jpg', '.jpeg', '.webp', '.eml']
            )
            doc_status = gr.Textbox(
                label="⬡ ANALYSIS OUTPUT",
                value="⬡ SYSTEM IDLE - AWAITING INPUT",
                lines=15,
                elem_id="doc-status"
            )
            clear_btn = gr.Button("⬡ CLEAR", size="lg")

        with gr.Column(scale=2):
            chat_interface = gr.ChatInterface(
                fn=chat,
                chatbot=gr.Chatbot(height=600),
                textbox=gr.Textbox(placeholder="⬡ PASTE URL OR QUERY SYSTEM"),
                examples=[
                    "Analyze this for phishing",
                    "Is this link suspicious?",
                    "What are the red flags?",
                    "Rate the threat level"
                ]
            )

    gr.HTML("""
        <div style='border-top:3px solid #fff; padding:25px; text-align:center; background:#000;'>
            <p style='color:#fff; font-size:1.2em; letter-spacing:3px; margin:10px 0;'>⬡ OPERATIONAL CAPABILITIES</p>
            <div style='display:flex; justify-content:center; gap:30px; flex-wrap:wrap; margin:20px 0;'>
                <div style='border:1px solid #fff; padding:15px; min-width:200px;'>
                    <p style='color:#fff; margin:5px 0; font-size:0.9em;'>📎 MULTI-FORMAT SCAN</p>
                    <p style='color:#888; margin:5px 0; font-size:0.75em;'>EML • PDF • DOCX • IMG</p>
                </div>
                <div style='border:1px solid #fff; padding:15px; min-width:200px;'>
                    <p style='color:#fff; margin:5px 0; font-size:0.9em;'>🔗 LIVE URL ANALYSIS</p>
                    <p style='color:#888; margin:5px 0; font-size:0.75em;'>PASTE & DETECT</p>
                </div>
                <div style='border:1px solid #fff; padding:15px; min-width:200px;'>
                    <p style='color:#fff; margin:5px 0; font-size:0.9em;'>🌐 THREAT INTEL</p>
                    <p style='color:#888; margin:5px 0; font-size:0.75em;'>70+ AV ENGINES</p>
                </div>
            </div>
            <p style='color:#888; margin:20px 0; font-size:0.85em; font-family:Share Tech Mono, monospace;'>DEVELOPED BY MAX WOJCIECHOWSKI | M2 SILICON | HACKATHON 2026</p>
            <p style='color:#555; margin:5px 0; font-size:0.7em;'>⬡ AUTHORIZATION LEVEL: UNRESTRICTED ⬡</p>
        </div>
    """)

    file_upload.change(upload_document, inputs=[file_upload], outputs=[doc_status])
    clear_btn.click(clear_document, outputs=[file_upload, doc_status])

demo.launch(share=True, css=css)
