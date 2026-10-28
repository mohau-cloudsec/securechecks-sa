# SecureCheck SA 🔐🇿🇦

**National SME Cyber Risk Platform — Powered by Progress OpenEdge + Claude AI**

*Built for the OpenEdge + AIGS AI Innovation Challenge 2026*

![OpenEdge](https://img.shields.io/badge/OpenEdge-ABL-blue)
![Python](https://img.shields.io/badge/Python-3.9%2B-green)
![AI](https://img.shields.io/badge/AI-Claude-orange)
![POPIA](https://img.shields.io/badge/POPIA-Aligned-red)
![Languages](https://img.shields.io/badge/Languages-EN%20%7C%20isiZulu%20%7C%20Sesotho%20%7C%20Afrikaans-yellow)

---

## The Problem

South Africa has over 2 million small and medium businesses. Most handle sensitive personal data — client financial records, medical files, legal documents. Most have no idea if their systems are secure. Hiring a cybersecurity consultant costs R5,000–R20,000 per engagement — completely out of reach for a small business.

Meanwhile, POPIA (Protection of Personal Information Act) makes security legally required. Penalties reach **R10 million or 10 years imprisonment**. Most SMEs don't know where to start.

**This is the gap SecureCheck SA fills.**

---

## The Solution

SecureCheck SA is a 20-point AI-powered security assessment platform for any South African business. It asks plain-language yes/no questions, scores the business against industry-standard controls, and produces a full POPIA-aligned risk report in English, isiZulu, Sesotho or Afrikaans.

**OpenEdge is the trusted data backbone.** All 20 security controls, risk levels, POPIA section references, and remediation steps come from the OpenEdge security controls database. Claude explains the findings. It never invents them.

---

## Architecture

```
Business Owner
      │
      ▼
SecureCheck SA CLI (Python)
      │
      ├──► OpenEdge Database (openedge/security_checks.p)
      │    └── 20 security controls
      │    └── Risk levels (CRITICAL / HIGH / MEDIUM)
      │    └── POPIA section references
      │    └── Remediation steps
      │
      ├──► Score Engine (Python)
      │    └── Weighted scoring algorithm
      │    └── Risk classification
      │
      └──► AI Analysis Layer (Claude via the Anthropic API)
           └── Plain-language report generation
           └── Industry-specific context
           └── Multilingual output (EN / isiZulu / Sesotho / Afrikaans)
           └── 30-day action plan
                │
                ▼
         Security Report (.txt)
         Assessment Log (.csv)
```

**Key principle:** OpenEdge holds the facts. AI explains them. AI never invents risk scores, POPIA references or remediation steps.

---

## Features

- ✅ **20-point assessment** across 7 security domains
- ✅ **POPIA-aligned** — every control mapped to a specific POPIA section
- ✅ **Multilingual** — English, isiZulu, Sesotho, Afrikaans
- ✅ **Industry-specific** — 8 South African industry categories
- ✅ **Weighted risk scoring** — critical controls count more
- ✅ **AI-generated plain-language reports** — no jargon
- ✅ **30-day action plan** — prioritised and actionable
- ✅ **Assessment logging** — every assessment is recorded in a CSV file
- ✅ **OpenEdge as trusted data source** — AI explains, never invents

---

## Security Domains

| Domain | Controls | Highest Risk Level |
|---|---|---|
| Identity & Access | 3 | CRITICAL |
| Data Protection | 3 | CRITICAL |
| Network Security | 3 | HIGH |
| Device Security | 3 | HIGH |
| People & Awareness | 2 | HIGH |
| POPIA Compliance | 4 | CRITICAL |
| Incident Response | 2 | HIGH |

---

## Scoring

Each control has a weight (5–10) based on its risk level. The score is the share of total weight the business passes, from 0 to 100:

| Score | Rating |
|---|---|
| 85–100 | LOW RISK |
| 65–84 | MEDIUM RISK |
| 40–64 | HIGH RISK |
| 0–39 | CRITICAL RISK |

---

## How to Run

### Prerequisites
- Python 3.9 or newer
- An Anthropic API key ([console.anthropic.com](https://console.anthropic.com)) with credit on the account
- Progress OpenEdge Developer Kit (only needed for the ABL component)

### Setup

```bash
git clone https://github.com/mohau-cloudsec/securechecks-sa.git
cd securechecks-sa
pip install anthropic python-dotenv
```

Create a file named `.env` in the project root (next to the `app` folder) containing:

```
ANTHROPIC_API_KEY=your_key_here
```

You can copy `.env.example` as a starting point. Never commit your real `.env` file.

### Run the assessment

```bash
python app/main.py
```

You will be asked for the business name, owner name, industry and report language, then 20 yes/no questions. The report is printed on screen and saved as a `.txt` file, and the result is added to `assessment_log.csv`.

### Run the OpenEdge component

Open `openedge/security_checks.p` in Progress Developer Studio for OpenEdge and run it. It loads and displays all 20 security controls from the OpenEdge database, the trusted data source for the platform.

---

## Sample Output

*Illustrative excerpt of a generated report (wording varies by run):*

```
SECURECHECKS SA - SECURITY ASSESSMENT REPORT
Business: Thabo's Accounting | Score: 35/100 - CRITICAL RISK

## Executive Summary
Thabo's Accounting is at critical risk. Of 20 security controls assessed,
14 are failing, including all 4 POPIA compliance requirements...

## CRITICAL - Fix These This Week
1. [POPIA Section 55] Information Officer not appointed...
2. [POPIA Section 22] No breach response plan...
...
```

---

## Evaluation Test Cases

See `eval/test_cases.md` for 5 test cases including edge cases and failure scenarios.

---

## Limitations & What's Next

- Currently a command-line app. Next version: web interface.
- OpenEdge integration uses mirrored data. Next version: live REST API calls.
- Report output is plain text. Next version: branded PDF.
- Could expand to 50+ controls for enterprise use.
- Reports are guidance, not legal advice. Businesses should confirm POPIA obligations with the Information Regulator or a legal professional.

---

## Why This Matters for South Africa

- 2 million+ SA SMEs need affordable security guidance
- POPIA enforcement is increasing, and businesses face real legal risk
- Most existing tools are built for UK/US compliance frameworks
- Language barriers exclude millions of business owners from English-only tools
- SecureCheck SA is built for South Africa, by South Africa

---

## Built By

**Mohau Bengo**
Higher Certificate in Cybersecurity — Academic Institute of Excellence (AIE)
[github.com/mohau-cloudsec](https://github.com/mohau-cloudsec) | [linkedin.com/in/mohau-bengo](https://linkedin.com/in/mohau-bengo)

*"From the East Rand to securing SA businesses — one check at a time."*

---

## About the OpenEdge + AI Architecture

This project demonstrates how Progress OpenEdge can serve as a trusted, structured data foundation for AI-powered business applications. The security controls database in OpenEdge provides authoritative, version-controlled data. The AI layer makes that data accessible to non-technical business owners in their own language. This separation — trusted data in OpenEdge, explanation in AI — is the core architectural principle of SecureCheck SA.

> *"OpenEdge gives you reliable data and business rules. AI makes them easier to reach, explain and use."* — OpenEdge Hackathon Starter Kit