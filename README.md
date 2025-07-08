# JSRecon

> 🔍 Extract juicy endpoints, secrets, tokens, and API paths from JavaScript files like a pro.

JSRecon is a fast and flexible Python-based tool that scrapes, downloads, and parses JavaScript files from a given website to uncover hidden treasures like:

- API endpoints
- Hardcoded URLs
- Secrets (API keys, tokens, JWTs)
- Interesting file paths

Perfect for recon, bug bounty, or red team workflows.

---

## 🧠 Why Use It?

Client-side JavaScript often exposes **backend logic** or **hidden API routes** that don’t show up in a crawler. JSRecon helps you:

- Discover undocumented API endpoints
- Identify sensitive hardcoded secrets
- Build custom wordlists for further fuzzing
- Feed data into tools like `ffuf`, `x8`, or `nuclei`

---

## ⚙️ Features

- ✅ Auto-fetches and parses all linked JS files
- ✅ Extracts structured data into categories
- ✅ Outputs clean, grouped `.txt` report
- ✅ Works smoothly in CLI environments (Kali, Termux, VSCode, etc.)
- ✅ ASCII banner included for ✨ vibes

---

## 🚀 Usage

```bash
git clone https://github.com/yourhandle/JSRecon.git
cd JSRecon
pip install -r requirements.txt
python JSRecon.py
