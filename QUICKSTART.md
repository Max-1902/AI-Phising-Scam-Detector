# Quick Start

## Prerequisites

- Mac with Apple Silicon (MLX doesn't run on Intel or Linux)
- Python 3.10+
- 16GB RAM
- ~9GB free disk for the 8-bit model

## Install

```bash
python3 -m venv llama-env
source llama-env/bin/activate
pip install -r requirements.txt
```

The model (`mlx-community/Meta-Llama-3.1-8B-Instruct-8bit`) downloads on first launch. To use a copy you already have, put it in `./llama-mlx-8bit` or point `MODEL_PATH` at it.

## VirusTotal (optional)

Without a key the VirusTotal check is skipped and everything else still runs.

```bash
export VT_API_KEY="your_api_key_here"
```

Free keys: https://virustotal.com/gui/settings/apikey (4 requests/minute).

## Run

```bash
python web_chat_docs.py
```

Open http://127.0.0.1:7860. Loading the model takes a little while on first start.

## Quick test

Paste into the chat:

```
http://tqbsdnn.inovacegroup.com.br/4TCcBs4563dxFl2146ypksottoen7534VMRFIZMYHTXYPMY1221WQAB231392j12
```

Expected flags: no HTTPS, random subdomain, tracking token in the path.

More:

```
http://paypa1.com/secure/login        typosquatting (PayPal)
https://paypal.com@evil.tk/login      '@' trick, real host is evil.tk
https://github.com/python/cpython     clean
```

## Troubleshooting

- **Model won't download**: check disk space and connection, or download it yourself and set `MODEL_PATH`.
- **VirusTotal shows HTTP 401**: key is wrong. Check `echo $VT_API_KEY`.
- **VirusTotal rate limit**: free tier allows 4 lookups/minute; each chat message can use up to 5.
- **Out of memory**: close other apps, 16GB is the practical minimum.
