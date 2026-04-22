# AI-Assisted Diamond Model Analyzer

A Python OOP capstone project that uses Google Gemini AI to analyze cyber incident scenarios through the **Diamond Model of Intrusion Analysis** framework.

The application extracts structured threat intelligence across four vertices — Adversary, Victim, Capability, and Infrastructure — and presents results in an interactive Streamlit interface with STIX export, PDF reporting, and analysis history.

---

## Features

- **AI-Powered Analysis** — Paste or upload an incident scenario and let Gemini AI map it to the Diamond Model
- **Evidence Extraction** — Automatically extracts IPs, domains, URLs, emails, CVEs, hashes, and attack keywords
- **Interactive Diamond Viewer** — Click each vertex to explore field values, confidence scores, and evidence
- **Validation & Scoring** — Completeness, confidence, and human review scores with analyst warnings
- **STIX Support** — Generate, edit, and re-import STIX 2.1-like bundles in-app
- **Export Options** — Download results as PDF report, JSON, or STIX bundle
- **Import Support** — Load previous JSON exports or STIX bundles back into the session
- **Analysis History** — Automatically saves the 10 most recent analyses as individual JSON files

---

## Requirements

### Python Version
Python **3.11 or higher** is required.

### Google Gemini API Key
This application uses the **Google Gemini API** to perform AI analysis.

You will need to obtain a free API key from Google AI Studio:

1. Go to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
2. Sign in with your Google account
3. Click **Create API Key**
4. Copy the key — you will paste it into the app when prompted

> Your API key is never stored by the application. It is entered at runtime in a password-masked input field.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/diamond-model-analyzer.git
cd diamond-model-analyzer
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> If you are using a virtual environment (recommended):
> ```bash
> python -m venv venv
> venv\Scripts\activate      # Windows
> source venv/bin/activate   # Mac / Linux
> pip install -r requirements.txt
> ```

---

## Running the Application

### Windows
Double-click the file: run.bat

## **Project Structure**
<img width="1246" height="864" alt="Component Diagram no background" src="https://github.com/user-attachments/assets/4b29a5d8-a6ac-4772-bb14-d74e60dc1261" />

## Dependencies

Key libraries used in this project:

| Library | Purpose |
|---|---|
| `streamlit` | Web UI framework |
| `langchain-google-genai` | Gemini AI integration via LangChain |
| `reportlab` | PDF report generation |

Install all dependencies with:
```bash
pip install -r requirements.txt
```

---

## Example Scenario
Please check the tests folder where you can find 4 different scenarios to test this system.

---

## Notes

- Analysis history is saved automatically in the `data/` folder
- Only the 10 most recent analyses are kept — older files are deleted automatically
- The `data/` folder is created automatically on first run
- API keys are never saved to disk

---

## License

This project was developed as a Python OOP capstone project for academic purposes.

