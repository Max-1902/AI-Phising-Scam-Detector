# Phishing Threat Analyzer

Scam and phishing detector built for Hackathon 2026 by Max Wojciechowski.

Paste a URL or drop in an email, document or screenshot. Python rule checks (plus an optional VirusTotal lookup) do the detection, and a local Llama 3.1 8B model explains the results in plain English with a LOW / MEDIUM / HIGH / CRITICAL rating.

## What it checks

**URLs**
- Typosquatted brand names (`paypa1`, `g00gle`, `arnazon`, ...)
- `user@host` tricks like `https://paypal.com@evil.tk` (the browser goes to `evil.tk`)
- Raw IP addresses instead of a domain
- High-risk TLDs (`.tk`, `.xyz`, `.top`, ...)
- Deeply nested subdomains
- Link shorteners and redirect services (`bit.ly`, `t.co`, ...)
- Randomly generated subdomains, using vowel count and Shannon entropy
- Long random path segments that phishers use to track individual victims
- VirusTotal verdicts, if `VT_API_KEY` is set

**Emails (.eml)**
- SPF, DKIM and DMARC results from the headers
- Reply-To pointing somewhere other than From
- All links in both the plain-text and HTML parts

**Other files**
- PDF, DOCX and TXT text extraction
- OCR for screenshots (PNG, JPG, WEBP) with EasyOCR
- URLs hidden behind URL encoding or base64

## How it works

```
input (URL / file / screenshot)
  -> text extraction (OCR, PDF, DOCX, email parser, URL + base64 decoding)
  -> rule checks in Python + VirusTotal
  -> Llama 3.1 8B (MLX) writes the explanation and risk rating
  -> Gradio UI
```

The model never decides on its own whether something is malicious. Python produces the findings and the model only summarises them. Asked to judge raw URLs directly, the model tended to refuse or guess.

### Entropy check

Shannon entropy measures how random a string looks. Real subdomains (`www`, `mail`, `app`) score low. Generated ones (`tqbsdnn`, `xk7mq2`) score high or have no vowels at all.

### Tracking tokens

```
http://example.com/4TCcBs4563dxFl2146ypk...  <- flagged
http://example.com/login                      <- fine
```

Path segments longer than 20 characters that mix upper case, lower case and digits with high entropy get flagged.

## Setup

Needs a Mac with Apple Silicon (MLX), Python 3.10+ and 16GB RAM. See [QUICKSTART.md](QUICKSTART.md) for details.

```bash
pip install -r requirements.txt
export VT_API_KEY="your_api_key_here"   # optional
python web_chat_docs.py
```

Open http://127.0.0.1:7860.

| Variable       | Default                                            | Purpose                              |
|----------------|----------------------------------------------------|--------------------------------------|
| `VT_API_KEY`   | unset (check skipped)                              | VirusTotal API key                   |
| `MODEL_PATH`   | `./llama-mlx-8bit` if present, else the HF model   | MLX model folder or Hugging Face id  |
| `GRADIO_SHARE` | off                                                | `1` makes a public gradio.live link  |

## Privacy

- The model runs locally. Files and text are not sent to any AI service.
- If `VT_API_KEY` is set, every URL that gets scanned is sent to VirusTotal.
- By default the app only listens on localhost. `GRADIO_SHARE=1` exposes it publicly, so anyone with the link can use it and your VirusTotal quota.
- The app keeps no history or logs. Gradio holds uploaded files in its temp folder while it runs.

## Limitations

- The brand list is short and hand-written, so it only catches the exact misspellings listed.
- A brand name placed in a subdomain (`paypal.com.secure-login.tk`) isn't flagged by itself, though the TLD check often catches it.
- The entropy thresholds were tuned on a handful of samples and can misfire on legitimate long IDs (some CDNs and cloud storage links).
- Uploaded content is passed to the model, so text inside a malicious email can try to steer the explanation. The rule findings above the explanation are not affected.

## Ideas for later

- Domain age via WHOIS
- Brand detection in subdomains and edit-distance matching instead of a fixed list
- Browser extension
- Batch scanning

## License

MIT

## Author

Max Wojciechowski, CS Master's student at DePaul University
