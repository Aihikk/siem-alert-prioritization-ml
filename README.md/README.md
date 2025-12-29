# 🛡️ SIEM Alert Prioritization using Machine Learning

## 📌 Project Overview
This project implements a **SOC (Security Operations Center) alert prioritization system** using Machine Learning.
It assigns a **risk score** to SIEM alerts, ranks them by priority, and provides **per-alert explainability** to help SOC analysts understand *why* an alert is risky.

---

## 🚀 Key Features
- ML-based alert risk scoring
- Priority-based alert queue
- SOC overview metrics
- Alert investigation panel
- Local explainability using SHAP

---

## 🏗️ Project Structure
```
SIEM-ALERT-PRIORITIZATION/
├── siem_features.csv
├── siem_alerts.csv
├── siem_alert_priority_model.pkl
├── dashboard.py
├── requirements.txt
├── README.md
└── Project_Report.md
```

---

## ▶️ How to Run
```bash
pip install -r requirements.txt
python -m streamlit run dashboard.py
```

---

## 📄 Author
**AIHIK CHAKRABORTY**
