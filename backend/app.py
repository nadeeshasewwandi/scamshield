import os
import re
import csv
import io
import json
import base64
import sqlite3
import joblib
import bcrypt
import jwt
import smtplib
from email.message import EmailMessage
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlencode
import urllib.request
import urllib.error
from flask import Flask, request, jsonify
from flask import send_file
from flask_cors import CORS
from PIL import Image, ImageOps
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import VotingClassifier

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
except ImportError:  # pragma: no cover - optional dependency
    A4 = None
    canvas = None

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:  # pragma: no cover - optional dependency
    pass

try:
    import pytesseract
    from pytesseract import TesseractNotFoundError
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
except Exception:  # pragma: no cover - optional dependency

    pytesseract = None
    TesseractNotFoundError = None

try:
    import pdfplumber
except ImportError:  # pragma: no cover - optional dependency
    pdfplumber = None

# ============================================================
# CONFIG
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model_store", "scam_model.joblib")
VECTORIZER_PATH = os.path.join(BASE_DIR, "model_store", "vectorizer.joblib")
DB_PATH = os.path.join(BASE_DIR, "scam_shield.db")
DATA_DIR = os.path.join(BASE_DIR, "data")
SPAM_CSV_PATH = os.path.join(DATA_DIR, "spam.csv")
CUSTOM_DATASET_PATH = os.path.join(DATA_DIR, "dataset.csv")
JWT_SECRET = os.environ.get("SCAM_SHIELD_JWT_SECRET", "super-secret-key-change-this")
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA = timedelta(days=7)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
OPENAI_API_URL = os.environ.get("OPENAI_API_URL", "https://api.openai.com/v1/chat/completions")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", "no-reply@scamshield.local")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ("1", "true", "yes")

os.makedirs(os.path.join(BASE_DIR, "model_store"), exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)


def load_external_datasets():
    """
    Loads real-world labeled data placed in /data:
      - dataset.csv        -> custom dataset (label,text columns)
    Returns (texts, labels) ready to merge with SEED_DATA.
    """
    texts = []
    labels = []

    if os.path.exists(CUSTOM_DATASET_PATH):
        try:
            df2 = pd.read_csv(CUSTOM_DATASET_PATH, encoding="utf-8")
            cols = [c.lower().strip() for c in df2.columns]
            df2.columns = cols
            label_col = "label" if "label" in cols else cols[0]
            text_col = "text" if "text" in cols else cols[1]
            df2 = df2.dropna(subset=[text_col, label_col])
            for _, row in df2.iterrows():
                raw_label = str(row[label_col]).strip().lower()
                label = 1 if raw_label in ("spam", "scam", "1", "phishing") else 0
                texts.append(str(row[text_col]))
                labels.append(label)
            print(f"[data] Loaded {len(df2)} rows from dataset.csv")
        except Exception as e:
            print(f"[data] Warning: could not load dataset.csv ({e})")

    return texts, labels

SINHALA_RANGE = re.compile(r'[\u0D80-\u0DFF]')
LATIN_RANGE = re.compile(r'[a-zA-Z]')

URGENCY_WORDS = {
    "english": [
        "urgent", "immediately", "verify now", "act now", "limited time",
        "click here", "suspended", "winner", "congratulations", "free gift",
        "claim now", "expire", "confirm your account", "update your information",
        "unauthorized access", "verify your identity", "limited offer",
        "you have won", "final notice", "account locked", "security alert"
    ],
    "sinhala": [
        "වහාම", "ත්‍යාගය", "ජයග්‍රාහකයා", "අත්හිටුවා", "ක්ලික් කරන්න",
        "ගිණුම අත්හිටුවා", "තහවුරු කරන්න", "ඔබ ජයග්‍රහණය කර ඇත", "නොමිලේ",
        "අවසන් දැනුම්දීම", "ලියාපදිංචි කරන්න", "ඔබගේ ගිණුම අවලංගු",
        "මුදල් ලබා ගන්න", "ක්ෂණිකව", "අනතුරු ඇඟවීම",
        "click karanna", "verify karanna", "password eka update", "account eka block",
        "ganak luck", "aarakshitha", "aakshitha", "block wenawa", "ethakota",
        "link ekata yanna", "claim karanna", "prize ekak", "bank-update.ga",
        "nathnam", "ban wenawa", "restore karanna", "account eka athulata",
        "log wenna", "hariyata update", "password eka", "close wenawa"
    ]
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".click"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"}
SUSPICIOUS_DOMAIN_KEYWORDS = ["secure-", "verify-", "login-", "account-", "update-", "confirm-", "-bank", "-pay"]
SUSPICIOUS_PHRASES = [
    "confirm your account", "verify your identity", "your account has been suspended", "password update",
    "claim now", "free gift", "limited time", "act now", "urgent", "click here", "account locked",
    "verify karanna", "password eka update", "account eka block", "link ekata yanna", "claim karanna",
    "bank update", "log wenna", "account eka athulata", "aaraakshitha", "nathnam ban wenawa"
]

# ============================================================
# SEED TRAINING DATA (English + Sinhala + Mixed)
# Replace / expand with full dataset (e.g. Kaggle SMS Spam Collection)
# for production-grade accuracy.
# ============================================================
SEED_DATA = [
    # --- SCAM / PHISHING (label = 1) ---
    ("Congratulations! You have won $1000. Click here to claim your prize now: http://bit.ly/claim123", 1),
    ("URGENT: Your bank account has been suspended. Verify your identity immediately at secure-bankverify.tk", 1),
    ("You have been selected for a free iPhone. Claim now before offer expires! http://win-prize.xyz/claim", 1),
    ("Dear customer, your package could not be delivered. Confirm your address here: http://delivery-update.club", 1),
    ("Your account will be locked in 24 hours. Update your information now to avoid suspension.", 1),
    ("FINAL NOTICE: Unauthorized access detected on your account. Verify now at login-secure.ga", 1),
    ("ඔබට ත්‍යාගයක් ලැබී ඇත! වහාම මෙම link එක click කර ඔබගේ ත්‍යාගය ලබා ගන්න http://prize-lk.tk", 1),
    ("ඔබගේ බැංකු ගිණුම අත්හිටුවා ඇත. වහාම තහවුරු කරන්න නැතිනම් ගිණුම අවලංගු වේ.", 1),
    ("ඔබ රු. 50000 ක මුදලක් දිනා ඇත! මෙතනින් ලියාපදිංචි කර මුදල් ලබාගන්න http://lucky-win.club", 1),
    ("ඔබගේ Mobile account එක අද රාත්‍රිය තුළ අත්හිටුවනු ඇත. ක්ෂණිකව මෙම link එක click කරන්න.", 1),
    ("Click here to update your password immediately or lose access to your email: secure-mail-update.work", 1),
    ("You've been chosen as our lucky winner of a brand new car! Confirm your details now at car-win-now.top", 1),
    ("Bank ekata log wenna methana click karanna nathnam account eka suspend wenawa http://verify-bank.cf", 1),
    ("ඔබගේ ATM card එක block වී ඇත. PIN number එක මෙතන enter කරන්න http://atm-secure.ml", 1),
    ("Limited time offer! Get 90% off, click now before it's too late: http://mega-sale-deal.xyz", 1),
    ("ඔයාට මේ ලින්ක් එකේ click කරලා අලුත් password එක update කරන්න ඕනෙ. නැත්නම් account එක block වෙනවා.", 1),
    ("thawath thiyenawa prize ekak. oya log karanna http://secure-login.ga kiyala address ekata.", 1),
    ("oya hariyata balanna. account eka verify karanna http://bank-update.tk", 1),
    ("mama kiyannawa. oba ge bank account eka secure karanna. methana click karanna.", 1),
    ("ape api geniyanna kiyala wage email ekak. link ekata yanna epa.", 1),
    ("oya godak luck ekak thiyenawa. click karanna http://bank-update.ga ethakota aarakshitha wei", 1),
    ("We detected suspicious login attempt. Verify your identity here within 1 hour: account-verify-now.gq", 1),
    ("Your tax refund of $850 is ready. Claim it now by confirming your bank details: tax-refund-claim.tk", 1),
    ("ඔබගේ ජංගම දුරකථන අංකය lottery එකකින් ජයග්‍රහණය කර ඇත. විස්තර සඳහා ක්ලික් කරන්න.", 1),
    ("Act now! Your subscription will be cancelled unless you update payment info at pay-update-secure.club", 1),
    ("CONGRATULATIONS you are today's winner, claim your gift card immediately: http://gift-claim-fast.top", 1),

    # --- LEGITIMATE (label = 0) ---
    ("Hi, are we still meeting for lunch tomorrow at 12?", 0),
    ("Your order #4521 has been shipped and will arrive in 3-5 business days.", 0),
    ("Reminder: Your dentist appointment is scheduled for Friday at 10 AM.", 0),
    ("Thanks for the great presentation today, the client was impressed.", 0),
    ("Can you send me the updated project report by end of day?", 0),
    ("ඔයා heta office ekata enawada? meeting eka 9.30ta.", 0),
    ("අද සවස 6ට class එක තියෙනවා, late වෙන්න එපා.", 0),
    ("ලඟදීම ඔයාගේ assignment eka submit karanna ona, deadline eka heta.", 0),
    ("Your electricity bill for this month is Rs. 4500, due on the 25th.", 0),
    ("Happy birthday! Hope you have a wonderful day with family.", 0),
    ("Mage exam result eka tikak balanna puluwanda, kohomada thiyenne kiyala dannath ona.", 0),
    ("The meeting has been rescheduled to 3 PM tomorrow in conference room B.", 0),
    ("Could you please review the attached document and share your feedback?", 0),
    ("අම්මේ, මම today late වෙයි ආයෙ ගෙදර එන්න, traffic වැඩියි.", 0),
    ("Your monthly bank statement is now available in your online banking portal.", 0),
    ("Thank you for your purchase, your invoice is attached for your records.", 0),
    ("Let's catch up this weekend, it's been a while since we talked.", 0),
    ("ක්ලාස් eka start wenne 8.30ta, lecture hall 2 eke.", 0),
    ("Please find attached the minutes of yesterday's meeting for your reference.", 0),
    ("Your library book is due for return on the 30th of this month.", 0),
    ("mama office ekata yanawa. hithanna puluwan nam call karanna", 0),
    ("oya honda ne, mata lunch ekata yanawa. ehema kiyanna puluwan nam call karanna", 0),
    ("oya mata den awa. passe dannawa mokakda karanne kiyala.", 0),
    ("ඔබට යාලුවෙක්ගෙන් කතා කරන්න කියලා කියලා. කකුලු කැඩෙන්නෙ නැහැ.", 0),
    ("api kalinham kiyala thiyenne, office ekata gana kiyanna one.", 0),
    ("mama ayeth danawada kiyala balanna. issara wage ne.", 0),
    ("එයා අද සවසට පැමිණෙනවා. අපි රැස්වීම් එකක් තියෙනවා.", 0),
    ("oya eththa katha karanna. mama dena wara balanna.", 0),

    # Suspicious no-URL warnings
    ("oya password eka update karanna one. account eka block wenawa kiyala.", 1),
    ("mama kiyanna one, oya account eka verify karanna. nethnam close wenawa.", 1),
    ("bank account eka restore karanna one. ehema ne nathnam ban wenawa.", 1),
    ("account eka athulata log wenna. password eka hariyata update karanna.", 1),
]

# ============================================================
# TEXT PREPROCESSING
# ============================================================
class TextPreprocessor:
    @staticmethod
    def clean(text: str) -> str:
        text = text.strip()
        text = re.sub(r'\s+', ' ', text)
        # keep Sinhala unicode + latin letters/numbers + basic punctuation
        text = re.sub(r'[^\u0D80-\u0DFFa-zA-Z0-9\s.,!?@:/\-]', ' ', text)
        return text.strip()

    @staticmethod
    def extract_urls(text: str):
        url_pattern = re.compile(r'(https?://[^\s]+|www\.[^\s]+)')
        return url_pattern.findall(text)

    @staticmethod
    def strip_urls(text: str) -> str:
        return re.sub(r'(https?://[^\s]+|www\.[^\s]+)', ' ', text)


# ============================================================
# LANGUAGE DETECTION
# ============================================================
class LanguageDetector:
    SINGLISH_WORDS = {
        "oya", "mata", "api", "eka", "hari", "kohomada", "mage",
        "mama", "oba", "owage", "meka", "eyata", "thiyenawa",
        "thiyenne", "kala", "karanna", "danna", "balanna", "ayemath",
        "inna", "yanna", "nathi", "neme", "thamange", "asai",
        "passe", "hamotama", "puluwa", "puluwanda", "apiya",
        "mehema", "kewda", "mokada", "dan", "kissa", "epa", "ona",
        "etai", "wedha", "wela", "hora", "gala", "aluth", "innawa"
    }

    @staticmethod
    def detect(text: str) -> str:
        sinhala_chars = len(SINHALA_RANGE.findall(text))
        latin_chars = len(LATIN_RANGE.findall(text))
        total = sinhala_chars + latin_chars
        if total == 0:
            return "unknown"

        if sinhala_chars > 0:
            return "sinhala"

        text_lower = text.lower()
        latin_words = re.findall(r"[a-zA-Z]+", text_lower)
        singlish_matches = sum(1 for w in latin_words if w in LanguageDetector.SINGLISH_WORDS)

        if singlish_matches >= 1 and len(latin_words) <= 20:
            return "sinhala"

        sinhala_ratio = sinhala_chars / total if total > 0 else 0
        latin_ratio = latin_chars / total if total > 0 else 0

        if latin_ratio > 0.85:
            return "english"
        elif sinhala_ratio > 0:
            return "sinhala"
        elif singlish_matches > 0:
            return "sinhala"
        else:
            return "mixed"


# ============================================================
# URL ANALYZER
# ============================================================
class URLAnalyzer:
    @staticmethod
    def virustotal_lookup(url: str):
        if not VIRUSTOTAL_API_KEY:
            return None
        try:
            payload = urlencode({"url": url}).encode("utf-8")
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            submit = urllib.request.Request("https://www.virustotal.com/api/v3/urls", data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(submit, timeout=15) as response:
                analysis_id = json.loads(response.read().decode("utf-8"))["data"]["id"]
            encoded_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            lookup = urllib.request.Request(f"https://www.virustotal.com/api/v3/urls/{encoded_id}", headers=headers)
            with urllib.request.urlopen(lookup, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8"))
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0), "engines": sum(stats.values())}
        except Exception as exc:
            return {"error": str(exc)}

    @staticmethod
    def analyze(url: str) -> dict:
        reasons = []
        score = 0.0

        if not url.startswith("http"):
            url = "http://" + url

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
        except Exception:
            return {"url": url, "score": 0.5, "reasons": ["Could not parse URL structure"]}

        # IP address as domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            score += 0.35
            reasons.append("Domain is a raw IP address instead of a name")

        # No HTTPS
        if parsed.scheme != "https":
            score += 0.10
            reasons.append("Connection is not secured with HTTPS")

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 0.25
                reasons.append(f"Uses a high-risk domain extension ({tld})")
                break

        # URL shortener
        for shortener in URL_SHORTENERS:
            if shortener in domain:
                score += 0.15
                reasons.append("Uses a URL shortening service (hides real destination)")
                break

        # Suspicious keywords in domain
        for kw in SUSPICIOUS_DOMAIN_KEYWORDS:
            if kw in domain:
                score += 0.20
                reasons.append(f"Domain contains suspicious keyword pattern ('{kw.strip('-')}')")
                break

        # Excessive subdomains / hyphens
        if domain.count('-') >= 2:
            score += 0.10
            reasons.append("Domain contains an unusually high number of hyphens")
        if domain.count('.') >= 3:
            score += 0.10
            reasons.append("Domain has an excessive number of subdomains")

        # Long URL
        if len(url) > 75:
            score += 0.10
            reasons.append("URL is unusually long")

        score = min(score, 1.0)
        result = {"url": url, "score": round(score, 2), "reasons": reasons}
        virustotal = URLAnalyzer.virustotal_lookup(url)
        if virustotal:
            result["virustotal"] = virustotal
            if virustotal.get("malicious", 0) > 0:
                result["score"] = 1.0
                result["reasons"].append(f"VirusTotal detected this URL as malicious in {virustotal['malicious']} engine(s)")
        return result

    @classmethod
    def analyze_all(cls, urls: list) -> dict:
        if not urls:
            return {"max_score": 0.0, "details": []}
        details = [cls.analyze(u) for u in urls]
        max_score = max(d["score"] for d in details)
        return {"max_score": max_score, "details": details}


# ============================================================
# ML CLASSIFIER (TF-IDF + Voting Ensemble)
# ============================================================
class ScamClassifier:
    def __init__(self):
        self.vectorizer = None
        self.model = None
        self._load_or_train()

    def _load_or_train(self):
        if self._needs_retrain():
            self._train()
        else:
            self.model = joblib.load(MODEL_PATH)
            self.vectorizer = joblib.load(VECTORIZER_PATH)

    def _needs_retrain(self):
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
            return True

        model_time = os.path.getmtime(MODEL_PATH)
        vec_time = os.path.getmtime(VECTORIZER_PATH)
        data_times = []
        if os.path.exists(CUSTOM_DATASET_PATH):
            data_times.append(os.path.getmtime(CUSTOM_DATASET_PATH))

        if data_times and max(data_times) > min(model_time, vec_time):
            print("[train] Dataset changed since last model build. Retraining...")
            return True

        return False

    def _train(self):
        seed_texts = [t for t, _ in SEED_DATA]
        seed_labels = [l for _, l in SEED_DATA]

        ext_texts, ext_labels = load_external_datasets()

        raw_texts = seed_texts + ext_texts
        labels = seed_labels + ext_labels
        texts = [TextPreprocessor.clean(TextPreprocessor.strip_urls(t)) for t in raw_texts]

        print(f"[train] Training on {len(texts)} total examples "
              f"({len(seed_texts)} seed + {len(ext_texts)} from /data)")

        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True
        )
        X = self.vectorizer.fit_transform(texts)

        nb = MultinomialNB()
        lr = LogisticRegression(max_iter=1000)
        svc = CalibratedClassifierCV(LinearSVC(max_iter=5000))

        self.model = VotingClassifier(
            estimators=[("nb", nb), ("lr", lr), ("svc", svc)],
            voting="soft"
        )
        self.model.fit(X, labels)

        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.vectorizer, VECTORIZER_PATH)

    def predict(self, text: str):
        clean = TextPreprocessor.clean(TextPreprocessor.strip_urls(text))
        X = self.vectorizer.transform([clean])
        proba = self.model.predict_proba(X)[0]
        scam_proba = float(proba[1]) if len(proba) > 1 else float(proba[0])

        # top contributing tokens (explainability)
        feature_names = np.array(self.vectorizer.get_feature_names_out())
        tfidf_scores = X.toarray()[0]
        top_idx = tfidf_scores.argsort()[-6:][::-1]
        top_tokens = [feature_names[i] for i in top_idx if tfidf_scores[i] > 0]

        classifier_scores = {}
        for name, estimator in self.model.named_estimators_.items():
            score = estimator.predict_proba(X)[0]
            classifier_scores[name] = round(float(score[1] if len(score) > 1 else score[0]) * 100, 1)

        return scam_proba, top_tokens, classifier_scores

    def retrain_with_new_data(self, texts: list, labels: list):
        """Allows expanding the dataset later (e.g. more Sinhala examples) without rewriting code."""
        seed_texts = [t for t, _ in SEED_DATA]
        seed_labels = [l for _, l in SEED_DATA]
        ext_texts, ext_labels = load_external_datasets()

        all_raw = seed_texts + ext_texts + texts
        all_labels = seed_labels + ext_labels + labels
        all_texts = [TextPreprocessor.clean(TextPreprocessor.strip_urls(t)) for t in all_raw]

        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)
        X = self.vectorizer.fit_transform(all_texts)

        nb = MultinomialNB()
        lr = LogisticRegression(max_iter=1000)
        svc = CalibratedClassifierCV(LinearSVC(max_iter=5000))
        self.model = VotingClassifier(estimators=[("nb", nb), ("lr", lr), ("svc", svc)], voting="soft")
        self.model.fit(X, all_labels)

        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.vectorizer, VECTORIZER_PATH)


# ============================================================
# RISK SCORING + EXPLAINABLE AI
# ============================================================
class RiskScorer:
    @staticmethod
    def detect_urgency_keywords(text: str, language: str):
        text_lower = text.lower()
        found = []
        word_pools = URGENCY_WORDS["english"] + URGENCY_WORDS["sinhala"]
        for word in word_pools:
            if word.lower() in text_lower or word in text:
                found.append(word)
        return found

    @staticmethod
    def detect_suspicious_phrases(text: str):
        text_lower = text.lower()
        found = []
        for phrase in SUSPICIOUS_PHRASES:
            if phrase.lower() in text_lower:
                found.append(phrase)
        return found

    @staticmethod
    def highlight_terms(text: str):
        categories = []
        for category, words in (
            ("phishing", ["password", "pin", "credential", "login", "verify your identity", "bank details", "account details"]),
            ("spam", ["free", "winner", "prize", "gift", "offer", "lottery", "cash"]),
            ("urgent", URGENCY_WORDS["english"] + URGENCY_WORDS["sinhala"]),
        ):
            for word in words:
                match = re.search(re.escape(word), text, re.IGNORECASE)
                if match:
                    categories.append({"text": match.group(0), "start": match.start(), "end": match.end(), "category": category})
        return sorted(categories, key=lambda item: (item["start"], -(item["end"] - item["start"])))

    @staticmethod
    def compute(text_score: float, url_analysis: dict, urgency_words: list, suspicious_phrases: list, top_tokens: list, original_text: str = "", classifier_scores: dict | None = None):
        url_score = url_analysis["max_score"]
        has_urls = len(url_analysis["details"]) > 0

        if not has_urls and not urgency_words and not suspicious_phrases:
            combined = text_score
            if combined < 0.50:
                risk_level = "Safe"
            elif combined < 0.78:
                risk_level = "Suspicious"
            else:
                risk_level = "Scam"
        else:
            if has_urls:
                combined = (text_score * 0.55) + (url_score * 0.45)
            else:
                combined = text_score

            if urgency_words:
                combined = min(combined + 0.05 * min(len(urgency_words), 4), 1.0)
            if suspicious_phrases:
                combined = min(combined + 0.06 * min(len(suspicious_phrases), 4), 1.0)

            if url_score >= 0.35 and text_score >= 0.45:
                combined = min(combined + 0.08, 1.0)
            if url_score >= 0.60:
                combined = max(combined, 0.75)

            credential_language = bool(re.search(r"\b(password|pin|credential|login|bank details|verify your identity)\b", original_text, re.IGNORECASE))
            if has_urls and credential_language and combined >= 0.65:
                risk_level = "Phishing"
            elif combined < 0.35:
                risk_level = "Safe"
            elif combined < 0.65:
                risk_level = "Suspicious"
            else:
                risk_level = "Scam"

        reasons = []
        if urgency_words:
            reasons.append(f"Urgency / pressure language detected: {', '.join(urgency_words[:4])}")
        if suspicious_phrases:
            reasons.append(f"Suspicious phrase detected: {', '.join(suspicious_phrases[:4])}")
        if top_tokens:
            reasons.append(f"Keywords influencing classification: {', '.join(top_tokens[:5])}")
        for d in url_analysis["details"]:
            reasons.extend(d["reasons"])
        if not has_urls and not urgency_words and not suspicious_phrases and combined < 0.35:
            reasons.append("No suspicious patterns, keywords, or links detected")

        recommendation = {
            "Safe": "This message appears legitimate. No action needed.",
            "Suspicious": "Exercise caution. Do not click links or share personal information until verified.",
            "Scam": "Do not click any links or respond. This message shows strong signs of a scam attempt.",
            "Phishing": "Do not click the link or share credentials. Verify the sender through an official channel and report the message."
        }[risk_level]

        return {
            "risk_level": risk_level,
            "confidence": round(combined * 100, 1),
            "reasons": reasons if reasons else ["No significant risk indicators found"],
            "recommendation": recommendation,
            "highlighted_terms": RiskScorer.highlight_terms(original_text),
            "classifier_scores": classifier_scores or {}
        }


class AssistantResponder:
    @staticmethod
    def detect_language(message: str) -> str:
        if SINHALA_RANGE.search(message):
            return "sinhala"
        singlish_words = r"oya|oyata|mata|api|ape|meka|eka|mokak|mokadda|kohomada|karanna|krnne|kiyanne|puluwanda|thiyenawa|nathi|hari|balanna|danna|ganna|denna|yanna|wena|wenne|wlt|ekak|hoda|hondada|identify|account|password|link|verify|click|urgent|scam|phishing|hack|hacking|cyber|security"
        if re.search(rf"\b({singlish_words})\b", message.lower()):
            return "singlish"
        return "english"

    @staticmethod
    def respond(message: str, history: list) -> str:
        language = AssistantResponder.detect_language(message)
        text = message.lower().strip()

        def choose(en: str, si: str, sl: str) -> str:
            if language == "sinhala":
                return si
            if language == "singlish":
                return sl
            return en

        urgency = any(word in text for word in ["urgent", "immediately", "verify now", "account suspended", "blocked", "limited time", "act now"])
        credentials_request = any(word in text for word in ["password", "pin", "account details", "login details", "credentials", "verify your identity"])
        link_question = any(word in text for word in ["url", "link", "website", "site", "domain"]) or "http" in text or "www." in text
        report_question = any(word in text for word in ["report", "complain", "authority", "cybercrime", "register"])
        safe_question = any(word in text for word in ["safe", "legit", "legitimate", "not scam", "trust", "verify"])
        image_question = any(word in text for word in ["image", "screenshot", "photo", "picture", "scan image"])
        advice_question = any(word in text for word in ["should i", "what should i", "how do i", "how to", "can i", "what if"]) and any(word in text for word in ["click", "open", "reply", "send", "share", "give"])

        educational_phishing = any(phrase in text for phrase in [
            "what is phishing", "phishing meaning", "phishing examples", "explain phishing",
            "phishing kiyanne", "phishing kiyala", "phishing ගැන", "phishing කියන්නේ", "phishing යනු"
        ])
        educational_scam = any(phrase in text for phrase in [
            "what is a scam", "what is scam", "scam meaning", "explain scam", "scam kiyanne", "scam kiyala",
            "scam ගැන", "scam කියන්නේ", "scam යනු"
        ])
        malware_question = any(word in text for word in [
            "malware", "virus", "trojan", "spyware", "ransomware", "මැල්වෙයාර්", "වයිරස්", "වෛරස"
        ])
        account_hacked = any(phrase in text for phrase in [
            "hacked", "account eka hack", "account hack", "account compromise", "someone accessed",
            "account එක hack", "account එක හැක්", "ගිණුම හැක්", "ගිණුමට කෙනෙක්"
        ])
        two_factor = any(phrase in text for phrase in [
            "2fa", "two factor", "two-factor", "otp", "multi factor", "mfa", "දෙපියවර", "ද්වි සාධක"
        ])
        system_question = any(phrase in text for phrase in [
            "how scamshield", "how does this system", "how does the system", "ai detection", "model work", "ensemble", "classifier",
            "scamshield කොහොමද", "system eka kohomada", "system එක කොහොමද", "ai එක වැඩ", "model එක වැඩ"
        ])
        cyber_question = any(word in text for word in [
            "cyber security", "cybersecurity", "online safety", "internet safety", "සයිබර් ආරක්ෂාව",
            "අන්තර්ජාල ආරක්ෂාව", "online ආරක්ෂාව", "cyber security ගැන", "cybersecurity gena"
        ])
        hacking_question = any(word in text for word in [
            "hack", "hacking", "hacked", "cyber attack", "security breach", "data breach",
            "හැක්", "හෑක්", "සයිබර් ප්‍රහාර", "දත්ත කඩකිරීම"
        ])
        privacy_question = any(word in text for word in [
            "privacy", "personal data", "identity theft", "tracking", "private information",
            "පෞද්ගලිකත්ව", "පුද්ගලික තොරතුරු", "identity එක"
        ])
        email_question = any(word in text for word in [
            "email", "sms", "message", "whatsapp", "attachment", "ඊමේල්", "පණිවිඩ"
        ])
        url_identification_question = any(phrase in text for phrase in [
            "suspicious url eka identify", "suspicious url ekak identify", "suspicious url eka aduraganne",
            "url eka identify", "url ekak identify", "link eka identify", "link ekak identify",
            "suspicious link eka aduraganne", "suspicious url ගැන", "suspicious link ගැන"
        ])
        scam_protection_question = any(phrase in text for phrase in [
            "scam walin araksha", "scam walin berena", "scam eken araksha", "scam වලින් ආරක්ෂා",
            "scam වලින් බේරෙන්න", "scam එකෙන් ආරක්ෂා", "scam walin protect", "avoid scams",
            "protect from scam", "stay safe from scam", "scam eken berena"
        ])

        if url_identification_question:
            return choose(
                "To identify a suspicious URL, check for HTTPS, misspelled brand names, strange subdomains, URL shorteners, urgent requests, and domains that do not match the real organization. Do not click it; open the official website manually and use ScamShield URL analysis first.",
                "Suspicious URL එකක් හඳුනාගන්න HTTPS තියෙනවාද, brand name එක වැරදි spelling එකකින්ද, strange subdomains තියෙනවාද, URL shortener එකක්ද, urgent request එකක්ද බලන්න. Link එක click නොකර official website එක manually open කරලා ScamShield URL analysis භාවිතා කරන්න.",
                "Suspicious URL ekak identify karanna HTTPS thiyenawada, brand name eka misspell wela da, strange subdomains thiyenawada, URL shortener ekak da, urgent request ekak da balanna. Link eka click nokara official website eka manually open karala ScamShield URL analysis use karanna."
            )

        if scam_protection_question:
            return choose(
                "To protect yourself from scams: pause before acting, do not click unexpected links, never share passwords or OTPs, verify the sender independently, use unique passwords and 2FA, update your devices, and report suspicious messages. ScamShield can analyze the message and URL, but always verify important requests through official channels.",
                "Scam වලින් ආරක්ෂා වෙන්න ඉක්මනින් act කරන්න එපා, unexpected links click කරන්න එපා, passwords හෝ OTPs share කරන්න එපා, sender වෙනම official channel එකකින් verify කරන්න, unique passwords සහ 2FA use කරන්න, devices update කරන්න, suspicious messages report කරන්න. ScamShield message සහ URL analyze කරයි, නමුත් වැදගත් requests official channels වලින් verify කරන්න.",
                "Scam walin araksha wenna hurry wela act karanna epa, unexpected links click karanna epa, passwords/OTPs share karanna epa, senderwa independently verify karanna, unique passwords saha 2FA use karanna, devices update karanna, suspicious messages report karanna. ScamShield message saha URL analyze karanawa, namuth important requests official channels walin verify karanna."
            )

        if educational_phishing:
            return choose(
                "Phishing is a cyber attack that impersonates a trusted person or organization to steal passwords, OTPs, card details, or money. Warning signs include urgency, unexpected links, fake domains, attachments, and requests for confidential information. Verify through the official website or phone number, not the message link.",
                "Phishing කියන්නේ විශ්වාස කරන organization එකක් හෝ පුද්ගලයෙක් වගේ පෙනී සිටලා password, OTP, card details හෝ මුදල් ගන්න කරන cyber attack එකක්. Urgent message, fake link/domain, attachment සහ confidential information ඉල්ලීම warning signs. Message link එක වෙනුවට official website/phone number එකෙන් verify කරන්න.",
                "Phishing kiyala trusted person/company ekak wage penila password, OTP, card details nathnam salli ganna try karana cyber attack ekak. Urgent message, fake domain/link, attachment, confidential info illima warning signs. Message eke link eka use nokara official website or phone number eken verify karanna."
            )

        if educational_scam:
            return choose(
                "A scam is deliberate deception used to steal money, information, access, or identity. Scams may arrive by SMS, email, phone call, social media, fake jobs, prizes, investments, or support messages. Pause, verify independently, and never share passwords or OTPs.",
                "Scam කියන්නේ මුදල්, තොරතුරු, account access හෝ identity එක සොරකම් කරන්න කරන වංචාවක්. SMS, email, calls, social media, fake jobs, prizes, investments හෝ support messages ලෙස එන්න පුළුවන්. ඉක්මන් නොවී වෙනම official channel එකකින් verify කරන්න; password හෝ OTP දෙන්න එපා.",
                "Scam kiyala salli, information, account access nathnam identity eka horakam karanna karana deception ekak. SMS, email, calls, social media, fake jobs, prizes, investments wage widihata enna puluwan. Hurry wenna epa, independently verify karanna, password/OTP denna epa."
            )

        if malware_question:
            return choose(
                "Malware is malicious software such as viruses, trojans, spyware, and ransomware. Do not open unexpected attachments or install unknown software. Update your device, use reputable security software, back up important files, and disconnect an infected device from the network.",
                "Malware කියන්නේ virus, trojan, spyware සහ ransomware වගේ හානිකර software. නොදන්නා attachment open කරන්න හෝ unknown software install කරන්න එපා. Device update කරන්න, trusted security software භාවිතා කරන්න, files backup කරන්න, infection එකක් සැක නම් network එකෙන් disconnect කරන්න.",
                "Malware kiyala virus, trojan, spyware, ransomware wage harmful software. Unknown attachment open karanna epa, unknown software install karanna epa. Device update karanna, trusted security software use karanna, files backup karanna, infection ekak nam network eken disconnect karanna."
            )

        if two_factor:
            return choose(
                "Two-factor authentication adds a second proof of identity after your password, such as an authenticator-app code or security key. Enable it for email, banking, and social accounts. Never give an OTP to someone who calls or messages you.",
                "Two-factor authentication කියන්නේ password එකට අමතරව authenticator code එකක් හෝ security key එකක් භාවිතා කරන ආරක්ෂාවක්. Email, banking සහ social accounts වල enable කරන්න. Call/message කරන කෙනෙකුට OTP එක කිසිම විටෙක දෙන්න එපා.",
                "2FA kiyala password ekata amatharawa authenticator code ekak nathnam security key ekak use karana protection ekak. Email, banking, social accounts walata enable karanna. Call/message karana kenekuta OTP eka denna epa."
            )

        if account_hacked:
            return choose(
                "If you think an account was hacked, change its password from the official website, sign out other sessions, enable 2FA, check recovery details and forwarding rules, and contact the provider. Do not use links from suspicious messages.",
                "Account එක hack වෙලා කියලා හිතෙනවා නම් official website එකට manually ගිහින් password change කරන්න, අනෙක් sessions sign out කරන්න, 2FA enable කරන්න, recovery details/forwarding rules check කරන්න, provider ට contact කරන්න. Suspicious message links use කරන්න එපා.",
                "Account eka hack wela kiyala hithenawanam official website ekata manually gihilla password change karanna, other sessions sign out karanna, 2FA enable karanna, recovery details/forwarding rules check karanna, provider ta contact karanna. Suspicious links use karanna epa."
            )

        if system_question:
            return choose(
                "ScamShield combines an NLP ensemble, urgency and scam-language rules, URL risk analysis, language detection, and explainable highlights. Naive Bayes, Logistic Regression, and LinearSVC vote on the text; the final risk score also considers URLs and phishing indicators. Treat the result as guidance and verify important messages independently.",
                "ScamShield එක NLP ensemble model, urgency/scam language rules, URL risk analysis, language detection සහ explainable highlights එකට භාවිතා කරනවා. Naive Bayes, Logistic Regression සහ LinearSVC text එක ගැන vote කරනවා; final risk score එක URLs සහ phishing indicators ද සලකා බලනවා. වැදගත් messages වෙනම verify කරන්න.",
                "ScamShield NLP ensemble model, urgency/scam language rules, URL risk analysis, language detection saha explainable highlights combine karanawa. Naive Bayes, Logistic Regression, LinearSVC text eka gana vote karanawa; final risk score eka URLs saha phishing indicators balala hadanawa. Important messages independently verify karanna."
            )

        if cyber_question:
            return choose(
                "Cybersecurity means protecting your devices, accounts, networks, and personal information from attacks. Use strong unique passwords, enable 2FA, update software, avoid suspicious links and attachments, and verify unexpected requests through official channels.",
                "Cybersecurity කියන්නේ devices, accounts, networks සහ personal information attacks වලින් ආරක්ෂා කිරීමයි. Strong unique passwords භාවිතා කරන්න, 2FA enable කරන්න, software update කරන්න, suspicious links/attachments avoid කරන්න, unexpected requests official channels වලින් verify කරන්න.",
                "Cybersecurity kiyala devices, accounts, networks saha personal information attacks walin protect karana eka. Strong unique passwords use karanna, 2FA enable karanna, software update karanna, suspicious links/attachments avoid karanna, unexpected requests official channels walin verify karanna."
            )

        if hacking_question:
            return choose(
                "For hacking or a suspected cyber attack, disconnect the affected device if malware is suspected, change passwords from a clean device, revoke unknown sessions, enable 2FA, preserve logs and messages, update software, and contact the service provider or a cybercrime authority. Never share OTPs or credentials while asking for help.",
                "Hacking හෝ cyber attack එකක් සැක නම් malware තියෙනවා වගේ නම් affected device එක network එකෙන් disconnect කරන්න. Clean device එකකින් passwords change කරන්න, unknown sessions revoke කරන්න, 2FA enable කරන්න, messages/logs save කරන්න, software update කරන්න, service provider හෝ cybercrime authority එකට report කරන්න. OTP හෝ credentials share කරන්න එපා.",
                "Hacking nathnam cyber attack ekak suspect nam malware thiyenawa wage nam affected device eka network eken disconnect karanna. Clean device ekakin passwords change karanna, unknown sessions revoke karanna, 2FA enable karanna, messages/logs save karanna, software update karanna, provider nathnam cybercrime authority ekata report karanna. OTP/credentials share karanna epa."
            )

        if privacy_question:
            return choose(
                "Protect your privacy by limiting personal information shared online, using unique passwords and 2FA, checking app permissions, keeping accounts private, avoiding unknown downloads, and verifying privacy settings. Treat requests for identity documents, OTPs, or banking details as sensitive.",
                "Privacy ආරක්ෂා කරගන්න online share කරන personal information limit කරන්න, unique passwords සහ 2FA භාවිතා කරන්න, app permissions check කරන්න, accounts private තබන්න, unknown downloads avoid කරන්න, privacy settings verify කරන්න. Identity documents, OTPs හෝ banking details ඉල්ලන requests sensitive ලෙස සලකන්න.",
                "Privacy protect karanna online share karana personal information limit karanna, unique passwords saha 2FA use karanna, app permissions check karanna, accounts private thiyanna, unknown downloads avoid karanna, privacy settings verify karanna. Identity documents, OTPs nathnam banking details illana requests sensitive kiyala balanna."
            )

        if email_question:
            return choose(
                "For a suspicious email or message, inspect the sender address, links, urgency, spelling, attachments, and requests for money or credentials. Do not reply or click. Verify using a trusted official website or phone number, then report and delete it.",
                "Suspicious email හෝ message එකක sender address, links, urgency, spelling, attachments සහ money/credentials ඉල්ලනවාද බලන්න. Reply කරන්න හෝ click කරන්න එපා. Trusted official website/phone number එකෙන් verify කරලා report කර delete කරන්න.",
                "Suspicious email/message ekaka sender address, links, urgency, spelling, attachments saha money/credentials illanawada balanna. Reply nathnam click karanna epa. Trusted official website/phone number eken verify karala report karala delete karanna."
            )

        if any(word in text for word in ["scam", "phishing", "phish", "fraud", "dodgy", "suspicious"]) and not any(word in text for word in ["what is phishing", "phishing meaning", "phishing examples"]):
            return choose(
                "This looks like a scam or phishing attempt. Check for urgency, credential requests, or suspicious links. Do not click anything or share passwords.",
                "මෙම message එක scam/phishing attempt එකක් විය හැක. urgency, password/credentials ඉල්ලීම හෝ suspicious link එකක් තියෙනවාද බලන්න. click කරන්න එපා, password දෙන්න එපා.",
                "Meka scam/phishing attempt ekak wenna puluwan. Urgent requests, password request ekak, suspicious link ekak thiyenawanam balanna. Click karanna epa, password denna epa."
            )

        if report_question:
            return choose(
                "Save the message and report it to your bank or local cybercrime authority. Do not reply or share more personal details.",
                "මෙම message එක save කරලා ඔබේ bank එකට හෝ local cybercrime authority එකට report කරන්න. reply කරන්න එපා, තවත් personal details දීමට එපා.",
                "Message eka save karala bank ekata nathi nathnam cybercrime authority ekata report karanna. Reply karanna epa, personal details denna epa."
            )

        if image_question and safe_question:
            return choose(
                "Images and screenshots cannot be verified automatically as safe. If the image shows a suspicious link or asks for credentials, treat it as unsafe and verify through official channels.",
                "Image එක safe කියලා automaticව කියන්න බැහැ. image එකේ suspicious link එකක් හෝ credentials ඉල්ලීමක් තියේ නම් unsafe කියලා බලන්න, official channels වලින් verify කරන්න.",
                "Image eka safe kiyala balanna baha. Screenshot eke suspicious link ekak thiyenawanam, credentials request ekak thiyenawanam unsafe kiyala balanna, official channels ekata verify karanna."
            )

        if advice_question:
            return choose(
                "Do not reply, click, or share sensitive information. Verify the sender with a trusted official channel instead of using any link in the message.",
                "reply කරන්න එපා, click කරන්න එපා, sensitive information දීමට එපා. message එකේ link එක බලලා නොයන්න, trusted official channel එකෙන් verify කරන්න.",
                "Reply karanna epa, click karanna epa, sensitive info denna epa. Message eke link eka use karanna epa, trusted official channel eka use karala verify karanna."
            )

        if "what is phishing" in text or "phishing meaning" in text or "phishing examples" in text:
            return choose(
                "Phishing is a scam that tricks you into giving sensitive information or clicking malicious links. It often uses urgent warnings, fake websites, or prize offers.",
                "Phishing කියන්නේ ඔබගෙන් sensitive information හෝ malicious links click කරන්න උත්සාහ කරන scam එකක්. මෙහි urgent warnings, fake websites, හෝ prize offers වැනි tactics භාවිතා කරනවා.",
                "Phishing kiyala oyata sensitive information ganna, malicious link click karanna try karanna scam ekak. Urgent warnings, fake websites, prize offers use karanawa."
            )

        if safe_question and link_question:
            return choose(
                "Look for HTTPS, a normal domain name, and no strange prefixes or shortened links. When in doubt, type the website manually instead of clicking.",
                "HTTPS තියෙනවාද, domain එක සාමාන්‍යද, strange prefix එකක් හෝ shortener එකක් තියෙනවාද බලන්න. සැකයක් ඇත්තේ නම් link එක click නොකර website එක manualව type කරන්න.",
                "HTTPS thiyenawada, domain eka normalda, strange prefix nadda, shortener nadda balanna. Doubt ekak thiyenawanam link eka click karanna epa, website eka manual type karanna."
            )

        if credentials_request and urgency:
            return choose(
                "Requests for login, password, PIN, or identity verification with urgency are major phishing signs. Legitimate organizations do not ask for credentials by email or SMS.",
                "login, password, PIN හෝ identity verification urgency එකක් සමඟ ඉල්ලීම phishing සංකේතයකි. බොහෝ legitimate organizations email හෝ SMS හරහා credentials අයන්නේ නැහැ.",
                "Login/password/PIN kiyala urgent request ekak thiyenawanam phishing sign ekak. Real company ekak email/SMS eke through credentials ekak ganna epa."
            )

        if "email" in text and any(word in text for word in ["attachment", "invoice", "payment", "bank", "account"]):
            return choose(
                "Suspicious emails often ask you to download attachments, make payments, or update bank details. Do not open attachments unless you trust the sender.",
                "සැකිත email එකක් attachment එක open කරන්න, payment කරන්න, හෝ bank details update කරන්න කියලා ඉල්ලයි. sender එක trusted නම් පමණක් attachment open කරන්න.",
                "Suspicious email ekak attachment open karanna, payment karanna, bank details update karanna kiyanawa. Sender eka trusted nathnam attachment open karanna epa."
            )

        if link_question and ("http" in text or "www." in text):
            return choose(
                "That URL may be suspicious if it contains strange domain names, misspellings, or shorteners. Verify it manually before clicking.",
                "මේ URL එක suspicious විය හැක, domain name එක අමුතු හෝ වැරදි අකුරු තිබේ නම්. manualව verify කරලා පස්සේ click කරන්න.",
                "Link eka suspicious wenna puluwan, domain eka strange nadda, misspellings nadda, shortener nadda balanna. Manual verify karala click karanna."
            )

        if language == "sinhala":
            return "මෙය ScamShield cybersecurity assistant එකයි. Scam, phishing, hacking, malware, suspicious links, account security, privacy සහ online safety ගැන ප්‍රශ්නයක් අහන්න. Message එකක් හෝ URL එකක් සැක නම් මෙතැන දාන්න; password, OTP හෝ API key share කරන්න එපා."
        if language == "singlish":
            return "Meka ScamShield cybersecurity assistant eka. Scam, phishing, hacking, malware, suspicious links, account security, privacy saha online safety gena onama prashnayak ahanna. Message ekak nathnam URL ekak suspect nam methana danna; password, OTP, API key share karanna epa."
        return "I am the ScamShield cybersecurity assistant. Ask me about scams, phishing, hacking, malware, suspicious URLs, account security, privacy, online safety, or how this AI detection system works. You can also paste a suspicious message or URL, but never share passwords, OTPs, or API keys."


# ============================================================
# DATABASE
# ============================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_text TEXT,
            language TEXT,
            risk_level TEXT,
            confidence REAL,
            reasons TEXT,
            urls_found INTEGER,
            account TEXT DEFAULT 'guest',
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            name TEXT PRIMARY KEY,
            password_hash TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def ensure_db_schema():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(scans)")
    columns = [row[1] for row in cursor.fetchall()]
    if "account" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN account TEXT DEFAULT 'guest'")

    cursor.execute("PRAGMA table_info(accounts)")
    account_columns = [row[1] for row in cursor.fetchall()]
    if "password_hash" not in account_columns:
        cursor.execute("ALTER TABLE accounts ADD COLUMN password_hash TEXT")
    if "email" not in account_columns:
        cursor.execute("ALTER TABLE accounts ADD COLUMN email TEXT")

    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), (stored_hash or "").encode("utf-8"))
    except Exception:
        return False


def send_email_report(to_email: str, subject: str, body: str) -> None:
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("Email sending is not configured. Set SMTP_HOST, SMTP_USER, and SMTP_PASSWORD.")

    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)
    message.add_alternative(
        "<html><body style='font-family:Arial,sans-serif;color:#182033'>"
        "<h2 style='color:#6d28d9'>ScamShield Analysis Report</h2>"
        f"<pre style='white-space:pre-wrap;background:#f5f3ff;padding:16px;border-radius:8px'>{body}</pre>"
        "<p>Stay safe online. Verify unexpected requests through official channels.</p>"
        "</body></html>", subtype="html"
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            if SMTP_USE_TLS:
                server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)
    except Exception as exc:
        raise ValueError(f"Unable to send email: {exc}")


def generate_jwt(account: str) -> str:
    payload = {
        "sub": account,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + JWT_EXP_DELTA
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return {"error": "expired"}
    except jwt.InvalidTokenError:
        return {"error": "invalid"}


def get_account_from_request(require_token=False):
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        payload = decode_jwt(token)
        if isinstance(payload, dict) and payload.get("error"):
            return None
        return payload.get("sub", "guest")

    if require_token:
        return None

    account = request.args.get("account", "").strip()
    if account:
        return account

    return "guest"


def save_scan(input_text, language, result, urls_found, account="guest"):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scans (input_text, language, risk_level, confidence, reasons, urls_found, account, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            input_text[:500],
            language,
            result["risk_level"],
            result["confidence"],
            json.dumps(result["reasons"]),
            urls_found,
            account,
            datetime.utcnow().isoformat()
        )
    )
    conn.commit()
    conn.close()


def extract_bulk_messages(payload: str, content_type: str = "text/plain"):
    if not payload:
        return []

    text = str(payload).strip()
    if not text:
        return []

    if content_type and "csv" in content_type.lower():
        rows = list(csv.reader(io.StringIO(text)))
        if not rows:
            return []

        header = [cell.strip().lower() for cell in rows[0]]
        target_fields = {"message", "text", "content", "input", "body", "sms", "email", "data"}
        if header and any(field in target_fields for field in header):
            target = next((field for field in header if field in target_fields), None)
            if target:
                idx = header.index(target)
                messages = []
                for row in rows[1:]:
                    if not row:
                        continue
                    value = str(row[idx] if idx < len(row) else "").strip()
                    if value:
                        messages.append(value)
                if messages:
                    return messages

        return [row[0].strip() for row in rows[1:] if row and str(row[0]).strip()]

    return [line.strip() for line in text.splitlines() if line.strip()]


def analyze_text_content(text: str, account: str = "guest"):
    language = LanguageDetector.detect(text)
    urls = TextPreprocessor.extract_urls(text)
    url_analysis = URLAnalyzer.analyze_all(urls)
    text_score, top_tokens, classifier_scores = classifier.predict(text)
    urgency_words = RiskScorer.detect_urgency_keywords(text, language)
    suspicious_phrases = RiskScorer.detect_suspicious_phrases(text)
    result = RiskScorer.compute(
        text_score,
        url_analysis,
        urgency_words,
        suspicious_phrases,
        top_tokens,
        original_text=text,
        classifier_scores=classifier_scores,
    )
    result["language"] = language
    result["urls_analyzed"] = url_analysis["details"]
    result["text_model_score"] = round(text_score * 100, 1)
    save_scan(text, language, result, len(urls), account)
    return result


def extract_text_from_bytes(payload: bytes, filename: str):
    if not payload:
        return "", "No content found in uploaded file."

    name = (filename or "").lower()
    if name.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".gif")):
        try:
            image = Image.open(io.BytesIO(payload)).convert("RGB")
            image = ImageOps.grayscale(image)
            if pytesseract is None:
                return "", "OCR is not available because pytesseract is not installed."
            try:
                text = pytesseract.image_to_string(image)
            except Exception as exc:
                msg = str(exc)
                if TesseractNotFoundError and isinstance(exc, TesseractNotFoundError):
                    return "", "OCR failed because the Tesseract executable is not installed or is not in PATH. Install Tesseract and restart the backend."
                return "", f"Unable to read image content: {msg}"
            return text.strip(), None
        except Exception as exc:
            return "", f"Unable to read image content: {exc}"

    if name.endswith(".pdf"):
        if pdfplumber is None:
            return "", "PDF extraction is unavailable because pdfplumber is not installed."
        try:
            with pdfplumber.open(io.BytesIO(payload)) as pdf:
                text = "\n".join((page.extract_text() or "") for page in pdf).strip()
            return text, None
        except Exception as exc:
            return "", f"Unable to read PDF content: {exc}"

    if name.endswith((".txt", ".md", ".log", ".rtf")):
        return payload.decode("utf-8", errors="ignore").strip(), None

    if name.endswith(".csv"):
        text = payload.decode("utf-8", errors="ignore")
        messages = extract_bulk_messages(text, "text/csv")
        return "\n".join(messages), None

    if name.endswith(".json"):
        try:
            data = json.loads(payload.decode("utf-8", errors="ignore"))
            if isinstance(data, list):
                values = []
                for item in data:
                    if isinstance(item, str):
                        values.append(item)
                    elif isinstance(item, dict):
                        for key in ("text", "message", "content", "body", "input", "sms", "email", "data"):
                            if key in item and isinstance(item[key], str):
                                values.append(item[key])
                                break
                if values:
                    return "\n".join(values), None
            if isinstance(data, dict):
                for key in ("text", "message", "content", "body", "input", "sms", "email", "data"):
                    value = data.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip(), None
        except Exception:
            pass

    return payload.decode("utf-8", errors="ignore").strip(), None


def analyze_bulk_messages(messages: list, account: str = "guest"):
    results = []
    for message in messages:
        result = analyze_text_content(message, account)
        results.append({"text": message, **result})

    counts = {level: sum(1 for item in results if item["risk_level"] == level) for level in ["Safe", "Suspicious", "Scam", "Phishing"]}
    summary = {
        "total": len(results),
        "safe": counts.get("Safe", 0),
        "suspicious": counts.get("Suspicious", 0),
        "scam": counts.get("Scam", 0),
        "phishing": counts.get("Phishing", 0),
        "high_risk": counts.get("Scam", 0) + counts.get("Suspicious", 0),
    }
    return results, summary


# ============================================================
# FLASK APP
# ============================================================
app = Flask(__name__)
CORS(app)

init_db()
ensure_db_schema()
classifier = ScamClassifier()


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "ok",
        "service": "Scam Shield Backend",
        "message": "Backend is running. Use /api/scan, /api/history, /api/health."
    })


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Scam Shield Backend"})


@app.route("/api/auth/register", methods=["POST"])
def register_account():
    data = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", "")).strip()

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password are required"}), 400
    if "@" not in email or "." not in email:
        return jsonify({"error": "Please provide a valid email address"}), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    existing = conn.execute(
        "SELECT name FROM accounts WHERE name = ? OR email = ?", (username, email)
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Username or email already exists"}), 409

    conn.execute(
        "INSERT INTO accounts (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (username, email, hash_password(password), datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    token = generate_jwt(username)
    return jsonify({"status": "success", "account": username, "token": token})


@app.route("/api/auth/login", methods=["POST"])
def login_account():
    data = request.get_json(force=True, silent=True) or {}
    identifier = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not identifier or not password:
        return jsonify({"error": "Username/email and password are required"}), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT name, email, password_hash FROM accounts WHERE name = ? OR email = ?",
        (identifier, identifier)
    ).fetchone()
    conn.close()

    if not row or not verify_password(password, row["password_hash"]):
        return jsonify({"error": "Invalid username/email or password"}), 401

    token = generate_jwt(row["name"])
    return jsonify({"status": "success", "account": row["name"], "email": row["email"], "token": token})


@app.route("/api/account", methods=["GET"])
def get_account():
    account = get_account_from_request(require_token=True)
    if account is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT name, email, created_at FROM accounts WHERE name = ?",
        (account,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Account not found"}), 404

    return jsonify({"account": row["name"], "email": row["email"], "created_at": row["created_at"]})


@app.route("/api/report", methods=["POST"])
def send_report():
    account = get_account_from_request(require_token=True)
    if account is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    data = request.get_json(force=True, silent=True) or {}
    text = str(data.get("text", "")).strip()
    if not text:
        return jsonify({"error": "No text provided to report"}), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT name, email FROM accounts WHERE name = ?", (account,)).fetchone()
    conn.close()

    if not row or not row["email"]:
        return jsonify({"error": "Your account does not have a registered email address"}), 400

    try:
        result = analyze_text_content(text, account)
        subject = f"Scam Shield report for {account}"
        body = [
            f"Hello {row['name']},",
            "",
            "Here is your Scam Shield analysis report:",
            "",
            f"Message analyzed:\n{text}",
            "",
            f"Risk level: {result['risk_level']}",
            f"Confidence: {result['confidence']}%", 
            f"Language: {result.get('language', 'unknown')}",
            f"Text model score: {result.get('text_model_score', 0)}%",
            "",
            "Reasons:",
            *[f"- {line}" for line in result.get('reasons', [])],
            "",
            "URL analysis:",
            *[f"- {u['url']}: {u['score']*100:.0f}% ({', '.join(u['reasons'])})" for u in result.get('urls_analyzed', [])],
            "",
            f"Recommendation: {result.get('recommendation', '')}",
            "",
            "Stay safe,",
            "Scam Shield Team"
        ]
        email_body = "\n".join(body)
        send_email_report(row["email"], subject, email_body)
        return jsonify({"status": "success", "message": f"Report sent to {row['email']}"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/report/pdf", methods=["POST"])
def download_report_pdf():
    if canvas is None:
        return jsonify({"error": "PDF generation is unavailable. Install reportlab."}), 503

    data = request.get_json(force=True, silent=True) or {}
    text = str(data.get("text", "")).strip()
    if not text:
        return jsonify({"error": "No text provided for the report"}), 400

    account = get_account_from_request()
    if account is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    result = analyze_text_content(text, account)
    stream = io.BytesIO()
    pdf = canvas.Canvas(stream, pagesize=A4)
    width, height = A4
    y = height - 54

    def line(value, size=10, gap=15):
        nonlocal y
        if y < 54:
            pdf.showPage()
            y = height - 54
        pdf.setFont("Helvetica", size)
        pdf.drawString(48, y, str(value)[:115])
        y -= gap

    pdf.setTitle("ScamShield Analysis Report")
    pdf.setFillColorRGB(0.31, 0.12, 0.60)
    line("ScamShield Analysis Report", 18, 28)
    pdf.setFillColorRGB(0, 0, 0)
    line(f"Generated: {datetime.utcnow().isoformat()} UTC")
    line(f"Risk level: {result['risk_level']} | Risk score: {result['confidence']}%", 12, 20)
    line(f"Language: {result.get('language', 'unknown')} | URLs found: {len(result.get('urls_analyzed', []))}")
    line("Message:", 12, 18)
    for part in text.splitlines() or [text]:
        line(part)
    line("Detection reasons:", 12, 18)
    for reason in result.get("reasons", []):
        line(f"- {reason}")
    line("URL analysis:", 12, 18)
    for url in result.get("urls_analyzed", []):
        line(f"- {url['url']} ({url['score'] * 100:.0f}%): {'; '.join(url['reasons'])}")
    line("Security recommendation:", 12, 18)
    line(result.get("recommendation", ""))
    pdf.save()
    stream.seek(0)
    return send_file(stream, mimetype="application/pdf", as_attachment=True, download_name="scamshield-analysis.pdf")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text", "").strip()
    account = get_account_from_request()
    if account is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    if not text:
        return jsonify({"error": "No text provided"}), 400

    result = analyze_text_content(text, account)
    return jsonify(result)


@app.route("/api/analyze-upload", methods=["POST"])
def analyze_upload():
    account = get_account_from_request()
    if account is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    file_storage = request.files.get("file")
    if not file_storage:
        return jsonify({"error": "No file uploaded"}), 400

    text, extraction_error = extract_text_from_bytes(file_storage.read(), file_storage.filename or "")
    if extraction_error and not text:
        return jsonify({"error": extraction_error, "extracted_text": ""}), 400

    if not text:
        return jsonify({"error": "No readable text found in uploaded file"}), 400

    result = analyze_text_content(text, account)
    return jsonify({
        "status": "success",
        "source": "upload",
        "extracted_text": text,
        "result": result,
        "ocr_meta": {"used": bool(file_storage.filename and file_storage.filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".gif")))},
    })


def call_openai_chat(message: str, history: list) -> str:
    if not OPENAI_API_KEY:
        raise ValueError("No OpenAI API key configured")

    messages = []
    if isinstance(history, list):
        for item in history:
            if not isinstance(item, dict):
                continue
            role = item.get("role")
            content = item.get("content")
            if role in {"user", "assistant", "system"} and isinstance(content, str):
                messages.append({"role": role, "content": content})

    messages.append({"role": "user", "content": message})

    payload = {
        "model": OPENAI_MODEL,
        "messages": messages,
        "max_tokens": 512,
        "temperature": 0.7,
        "top_p": 1.0
    }
    request_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OPENAI_API_URL,
        data=request_data,
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
            result = json.loads(raw)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        raise ValueError(f"OpenAI API error {e.code}: {body}")
    except urllib.error.URLError as e:
        raise ValueError(f"Could not reach OpenAI API: {e.reason}")

    if not isinstance(result, dict):
        raise ValueError("Invalid response from OpenAI API")

    if "error" in result:
        err = result["error"]
        raise ValueError(err.get("message") if isinstance(err, dict) else str(err))

    choices = result.get("choices") or []
    if not choices:
        raise ValueError("OpenAI API returned no choices")

    content = choices[0].get("message", {}).get("content", "").strip()
    if not content:
        raise ValueError("OpenAI API returned an empty message")

    return content


def call_gemini_chat(message: str, history: list) -> str:
    if not GEMINI_API_KEY:
        raise ValueError("No Gemini API key configured")
    contents = []
    if isinstance(history, list):
        for item in history:
            if isinstance(item, dict) and isinstance(item.get("content"), str):
                contents.append({
                    "role": "model" if item.get("role") == "assistant" else "user",
                    "parts": [{"text": item["content"]}],
                })
    contents.append({"role": "user", "parts": [{"text": message}]})
    request_body = json.dumps({
        "systemInstruction": {
            "parts": [{"text": "You are ScamShield AI Assistant, a cybersecurity specialist. Answer questions about scams, phishing, spam, malware, privacy, online safety, suspicious URLs, account security, and this AI-based scam detection system. Reply in the same language as the user: Sinhala script for Sinhala, Singlish for Romanized Sinhala, and English for English. For mixed messages, use the dominant language. Be clear, practical, and safe. Never ask users to share passwords, API keys, OTPs, or private credentials. If unrelated, redirect briefly to cybersecurity."}]
        },
        "contents": contents,
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": 600},
    }).encode("utf-8")

    models = [GEMINI_MODEL]
    for fallback_model in ("gemini-3.6-flash", "gemini-2.5-flash", "gemini-2.5-flash-lite"):
        if fallback_model not in models:
            models.append(fallback_model)
    payload = None
    last_error = None
    for model in models:
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
        req = urllib.request.Request(endpoint, data=request_body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            last_error = f"Gemini API error {exc.code}: {body}"
            if exc.code not in (404, 429, 500, 502, 503):
                raise ValueError(last_error)
    if payload is None:
        raise ValueError(last_error or "Gemini API returned no response")
    parts = ((payload.get("candidates") or [{}])[0].get("content") or {}).get("parts") or []
    answer = "".join(part.get("text", "") for part in parts).strip()
    if not answer:
        raise ValueError("Gemini API returned an empty response")
    return answer


@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json(force=True, silent=True) or {}
    message = data.get("message", "").strip()
    history = data.get("history", [])

    if not message:
        return jsonify({"error": "No message provided"}), 400

    if GEMINI_API_KEY:
        try:
            response = call_gemini_chat(message, history)
            return jsonify({"response": response, "source": "gemini"})
        except Exception as exc:
            # Gemini can be temporarily unavailable or rate-limited. Keep the
            # assistant usable with the local cybersecurity responder.
            response = AssistantResponder.respond(message, history)
            return jsonify({
                "response": response,
                "source": "fallback",
                "provider_warning": "Gemini is temporarily unavailable; using the built-in cybersecurity assistant."
            })

    if OPENAI_API_KEY:
        try:
            response = call_openai_chat(message, history)
            return jsonify({"response": response, "source": "openai"})
        except Exception as exc:
            return jsonify({"error": f"AI provider error: {str(exc)}"}), 502

    response = AssistantResponder.respond(message, history)
    return jsonify({"response": response, "source": "fallback"})


@app.route("/api/bulk-scan", methods=["POST"])
def bulk_scan():
    data = request.get_json(force=True, silent=True) or {}
    text = str(data.get("text", "") or "").strip()
    content_type = str(data.get("content_type", "text/plain") or "text/plain")
    account = get_account_from_request()
    if account is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    if not text:
        return jsonify({"error": "No text provided"}), 400

    messages = extract_bulk_messages(text, content_type)
    if not messages:
        return jsonify({"error": "No messages found to analyze"}), 400

    results, summary = analyze_bulk_messages(messages, account=account)
    return jsonify({"results": results, "summary": summary, "count": len(results)})


@app.route("/api/history", methods=["GET"])
def history():
    limit = request.args.get("limit", 50, type=int)
    account = get_account_from_request()
    if account is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if account:
        rows = conn.execute(
            "SELECT * FROM scans WHERE account = ? ORDER BY id DESC LIMIT ?", (account, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "input_text": r["input_text"],
            "language": r["language"],
            "risk_level": r["risk_level"],
            "confidence": r["confidence"],
            "reasons": json.loads(r["reasons"]),
            "urls_found": r["urls_found"],
            "created_at": r["created_at"]
        })
    return jsonify(results)


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    _ = request.get_json(force=True, silent=True) or {}
    account = get_account_from_request()
    if account is None:
        return jsonify({"error": "Invalid or expired token"}), 401
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans WHERE account = ?", (account,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "History cleared."})


@app.route("/api/stats", methods=["GET"])
def stats():
    account = get_account_from_request()
    if account is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if account:
        total = conn.execute("SELECT COUNT(*) c FROM scans WHERE account = ?", (account,)).fetchone()["c"]
        by_risk = conn.execute(
            "SELECT risk_level, COUNT(*) c FROM scans WHERE account = ? GROUP BY risk_level", (account,)
        ).fetchall()
        by_lang = conn.execute(
            "SELECT language, COUNT(*) c FROM scans WHERE account = ? GROUP BY language", (account,)
        ).fetchall()
    else:
        total = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        by_risk = conn.execute(
            "SELECT risk_level, COUNT(*) c FROM scans GROUP BY risk_level"
        ).fetchall()
        by_lang = conn.execute(
            "SELECT language, COUNT(*) c FROM scans GROUP BY language"
        ).fetchall()
    conn.close()

    # compute recent daily trend for the last 7 days
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    date_rows = conn.execute(
        "SELECT DATE(created_at) AS day, COUNT(*) AS c FROM scans WHERE created_at >= DATE('now', '-6 days')" +
        (" AND account = ?" if account else "") +
        " GROUP BY DATE(created_at) ORDER BY DATE(created_at)",
        (account,) if account else ()
    ).fetchall()
    conn.close()

    all_days = []
    today = datetime.utcnow().date()
    for idx in range(6, -1, -1):
        day = today - timedelta(days=idx)
        day_str = day.isoformat()
        all_days.append({
            "day": day_str,
            "count": next((row["c"] for row in date_rows if row["day"] == day_str), 0)
        })

    return jsonify({
        "total_scans": total,
        "by_risk_level": {r["risk_level"]: r["c"] for r in by_risk},
        "by_language": {r["language"]: r["c"] for r in by_lang},
        "daily_trend": all_days
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)