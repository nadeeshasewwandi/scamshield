# 🛡️ ScamShield
### AI-Based Multilingual Spam & Phishing Detection System


**HNDIT Final Year Project**


## 📌 About

ScamShield is an AI-powered web application that detects spam and phishing threats in **English**, **Sinhala (සිංහල)**, and **Singlish** — making it the first multilingual cybersecurity detection tool designed specifically for Sri Lankan users.

Users can paste suspicious messages, emails, or URLs and instantly receive an AI-powered threat classification — **Safe**, **Suspicious**, **Spam**, or **Phishing** — along with a risk score from 0 to 100% and a visual explanation of which words triggered the detection.

> 💡 Most existing spam filters only support English. ScamShield fills a critical gap by understanding how Sri Lankan users actually communicate online.


## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Message Analysis** | Scan SMS, emails, and text for spam and phishing threats |
| 🔗 **URL Scanner** | Heuristic analysis + VirusTotal API cross-check |
| ⚡ **Explainable AI (XAI)** | Highlights the exact words that triggered the detection |
| 🌐 **Multilingual** | English, Sinhala (Unicode), and Singlish supported |
| 📊 **Risk Scoring** | 0–100% risk score with animated visual bar |
| 📦 **Batch Analyze** | Upload CSV files to scan multiple messages at once |
| 📜 **Scan History** | Filter, search, and export past scan results |
| 🤖 **AI Assistant** | Google Gemini-powered cybersecurity chatbot |
| 📈 **Dashboard** | Real-time threat statistics and activity charts |
| 📄 **PDF Reports** | Download detailed scan reports |
| 🔐 **Auth System** | JWT-based secure login and registration |



## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, Vite, Tailwind CSS, Recharts |
| **Backend** | Python, Flask, Flask-JWT-Extended |
| **ML Model** | scikit-learn — TF-IDF + Voting Ensemble |
| **Database** | SQLite |
| **External APIs** | VirusTotal API, Google Gemini API |
| **PDF Reports** | ReportLab |
| **Auth** | JWT (access + refresh tokens), bcrypt |



## 🧠 ML Model — How It Works

```
User Input (Text / URL)
        ↓
Language Detection → English | Sinhala | Singlish
        ↓
Text Preprocessing → Tokenize → Stopwords → Stem
        ↓
TF-IDF Vectorization (30,000 features)
        ↓
┌─────────────────────────────────────┐
│  Naive Bayes        (Classifier 1)  │
│  Logistic Regression (Classifier 2) │  ← Voting Ensemble
│  LinearSVC          (Classifier 3)  │
└─────────────────────────────────────┘
        ↓
Risk Score (0–100%) + Prediction
        ↓
XAI: Highlight Flagged Words
```



## 📁 Project Structure

```
scamshield/
├── backend/
│   ├── app/
│   │   ├── routes/          ← auth, analyze, history, batch, assistant, dashboard
│   │   ├── models/          ← ml_model.py
│   │   ├── services/        ← virustotal.py, gemini.py, xai.py, pdf_report.py
│   │   └── utils/           ← preprocessor.py, language_detector.py
│   ├── data/
│   │   └── dataset.csv
│   ├── model_store/
│   │   ├── scam_model.joblib
│   │   └── vectorizer.joblib
│   ├── app.py
│   ├── requirements.txt
│   └── .env.example
│
└── frontend/
    ├── src/
    │   ├── pages/           ← Dashboard, Analyze, History, Batch, Assistant, Settings
    │   ├── components/      ← Sidebar, Navbar, Charts
    │   ├── App.jsx
    │   └── main.jsx
    ├── package.json
    └── vite.config.js
```



## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git



### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

# Install dependencies
pip install -r requirements.txt
```


### 2. Train the ML Model

```bash
python generate_dataset.py
```

### 3. Start the Backend

```bash
python app.py
# Runs on http://127.0.0.1:8000
```

### 4. Frontend Setup

```bash
cd ../frontend
npm install
npm run dev
# Runs on http://127.0.0.1:5173
```



## 🗄️ Database

SQLite database with 4 tables:

| Table | Purpose |
|---|---|
| `users` | User accounts (id, name, email, password_hash) |
| `scan_results` | Every scan result with prediction, risk score, XAI highlights |
| `batch_jobs` | CSV batch scan job tracking |
| `chat_history` | AI assistant conversation history |



## 📊 Model Performance

| Metric | Score |
|---|---|
| Accuracy | ~97% |
| Precision | ~96% |
| Recall | ~97% |
| F1 Score | ~96% |

Trained on the [UCI SMS Spam Collection Dataset](https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset) + custom synthetic Sinhala and Singlish dataset.



## 🌐 Multilingual Detection

| Language | Detection Method |
|---|---|
| **English** | `langdetect` library |
| **Sinhala** | Unicode range `U+0D80–U+0DFF` character detection |
| **Singlish** | Custom regex pattern matching on common Singlish keywords |



## 🔒 Security

- JWT access tokens (15 min) + refresh tokens (7 days)
- Passwords hashed with **bcrypt**
- API keys stored in `.env` — never committed to GitHub
- Rate limiting on all API endpoints
- Input sanitization before ML processing


