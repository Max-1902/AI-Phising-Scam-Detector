# ⬡ PHISHING THREAT ANALYZER

**AI-Powered Scam Detection System**  
*Hackathon 2026 | Max Wojciechowski*

---

## Overview

A production-grade phishing detection system that combines local AI inference with advanced threat intelligence to identify malicious URLs, emails, and documents in real-time.

## Key Features

### Multi-Layer Detection Pipeline
- **URL Analysis**: Typosquatting detection, entropy-based subdomain scanning, victim-tracking token identification
- **Threat Intelligence**: VirusTotal integration with 70+ antivirus engine checks
- **Email Authentication**: SPF/DKIM/DMARC verification for .eml files
- **OCR Processing**: Extract and analyze text from screenshots and images

### Local AI Inference
- **Llama 3.1 8B** running locally on Apple Silicon (M2)
- **MLX optimization** for efficient on-device inference
- Python-first threat detection with AI-powered explanations

### Supported File Types
- Email files (`.eml`)
- Documents (`.pdf`, `.docx`, `.txt`)
- Screenshots (`.png`, `.jpg`, `.jpeg`, `.webp`)

---

## Technical Architecture

```
┌─────────────────────────────────────────────────────┐
│  Input (URL/File/Screenshot)                        │
└───────────────┬─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────┐
│  Extraction Layer                                    │
│  • URL Decoding (handles encoding/obfuscation)      │
│  • OCR (EasyOCR for images)                         │
│  • Document parsing (PyPDF2, python-docx)           │
└───────────────┬─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────┐
│  Detection Pipeline (Python)                        │
│  • Typosquatting check (brand database)            │
│  • Shannon entropy analysis                         │
│  • Subdomain randomness detection                   │
│  • Tracking token identification                    │
│  • VirusTotal API query                             │
│  • Email authentication (SPF/DKIM/DMARC)            │
└───────────────┬─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────┐
│  AI Explanation Layer (Llama 3.1)                   │
│  • Risk rating (LOW/MEDIUM/HIGH/CRITICAL)           │
│  • Plain English explanation                        │
└───────────────┬─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────┐
│  Gradio Web Interface                               │
└─────────────────────────────────────────────────────┘
```

---

## Setup & Installation

### Requirements
- macOS with Apple Silicon (M2/M3) or equivalent
- Python 3.10+
- 16GB+ RAM recommended

### Install Dependencies
```bash
pip install gradio mlx-lm PyPDF2 python-docx Pillow easyocr requests dnspython
```

### VirusTotal API Key
1. Create free account at [virustotal.com](https://virustotal.com)
2. Get API key from [settings](https://virustotal.com/gui/settings/apikey)
3. Set environment variable:
```bash
export VT_API_KEY="your_api_key_here"
```

### Run
```bash
python web_chat_docs.py
```

Access at: `http://127.0.0.1:7860`

---

## How It Works

### Entropy-Based Detection
The system uses Shannon entropy to measure URL randomness:
- Legitimate subdomains: `www`, `mail`, `app` → Low entropy
- Phishing subdomains: `tqbsdnn`, `xk7mq2` → High entropy

### Victim Tracking Token Detection
Identifies long randomized path segments used to track individual targets:
```
http://example.com/4TCcBs4563dxFl2146ypk...  ← FLAGGED
http://example.com/login                      ← CLEAN
```

### Typosquatting Database
Checks URLs against common brand impersonations:
- `paypa1.com` → Flags as PayPal impersonation
- `g00gle.com` → Flags as Google impersonation

---

## Demo Test Cases

Paste these URLs to see the system in action:

1. **Tracking Token Detection**  
   `http://tqbsdnn.inovacegroup.com.br/4TCcBs4563dxFl2146ypksottoen7534VMRFIZMYHTXYPMY1221WQAB231392j12`

2. **Typosquatting**  
   `http://paypa1.com/secure/login`

3. **Clean URL**  
   `https://github.com/anthropics/anthropic-sdk-python`

---

## Tech Stack

- **AI Model**: Llama 3.1 8B (8-bit quantized)
- **ML Framework**: MLX (Apple Silicon optimized)
- **OCR**: EasyOCR
- **Web Framework**: Gradio
- **Threat Intel**: VirusTotal API
- **Document Processing**: PyPDF2, python-docx
- **Email Parsing**: Python `email` library

---

## Performance

- **Local inference**: ~2-3 seconds per URL on M2 Mac
- **No cloud dependencies**: All AI processing on-device
- **VirusTotal rate limit**: 4 requests/minute (free tier)

---

## Security Considerations

- API keys stored as environment variables (not hardcoded)
- All processing happens locally (privacy-first)
- Read-only file operations
- No data persistence or logging

---

## Future Enhancements

- [ ] Domain age checking (WHOIS integration)
- [ ] Machine learning model for phishing text patterns
- [ ] Browser extension for real-time URL scanning
- [ ] Batch processing for security teams
- [ ] Custom brand database for enterprise users

---

## License

MIT

## Author

**Max Wojciechowski**  
CS Master's Student | DePaul University  
Focus: AI/ML & Cybersecurity

---

*Built for Hackathon 2026*
