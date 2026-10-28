import os
import re
import csv
import datetime
from pathlib import Path

import anthropic
from dotenv import load_dotenv

# Always load the .env file from the project root (the folder that contains "app")
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

API_KEY = os.getenv("ANTHROPIC_API_KEY")
if not API_KEY:
    raise SystemExit(
        "ANTHROPIC_API_KEY not found.\n"
        "Create a file named .env in the securechecks-sa folder (next to the 'app' folder) "
        "containing:\nANTHROPIC_API_KEY=your_key_here"
    )

client = anthropic.Anthropic(api_key=API_KEY)

MODEL = "claude-haiku-5-5"

SECURITY_CONTROLS = [
    {"id":1,"category":"Identity & Access","question":"Do all staff accounts have Multi-Factor Authentication (MFA) enabled?","risk":"CRITICAL","popia":"Section 19","remediation":"Enable MFA on every account. Use Microsoft Authenticator. Takes 10 minutes per user.","weight":10},
    {"id":2,"category":"Identity & Access","question":"Does every staff member have their own unique login with no shared passwords?","risk":"CRITICAL","popia":"Section 19","remediation":"Create individual accounts for each person. Use Bitwarden (free) for passwords.","weight":10},
    {"id":3,"category":"Identity & Access","question":"Do you review who has access to your systems at least every 6 months?","risk":"HIGH","popia":"Section 19","remediation":"Remove access for anyone who left or changed roles. Only give people what they need.","weight":8},
    {"id":4,"category":"Data Protection","question":"Is all client data stored in encrypted cloud storage or encrypted drives?","risk":"CRITICAL","popia":"Section 19","remediation":"Move to Microsoft OneDrive or Azure Blob Storage. Stop storing on USB drives.","weight":10},
    {"id":5,"category":"Data Protection","question":"Are automated backups running at least daily?","risk":"HIGH","popia":"Section 19","remediation":"Enable Microsoft 365 backup or Azure Backup. Test restore process monthly.","weight":8},
    {"id":6,"category":"Data Protection","question":"Do you know exactly where all your client data is stored?","risk":"HIGH","popia":"Section 14","remediation":"Create a data inventory listing every system, folder and device holding client data.","weight":8},
    {"id":7,"category":"Network Security","question":"Is your business WiFi protected with WPA2 or WPA3 encryption?","risk":"HIGH","popia":"Section 19","remediation":"Log into your router and enable WPA3. Change the default password. Takes 5 minutes.","weight":7},
    {"id":8,"category":"Network Security","question":"Do you have a separate WiFi network for guests and personal devices?","risk":"MEDIUM","popia":"Section 19","remediation":"Create a guest network on your router separate from business devices.","weight":5},
    {"id":9,"category":"Network Security","question":"Are all computers and devices running up-to-date software and security patches?","risk":"HIGH","popia":"Section 19","remediation":"Enable automatic updates on all Windows PCs and mobile devices.","weight":8},
    {"id":10,"category":"Device Security","question":"Are all business laptops and computers protected with a password or PIN?","risk":"HIGH","popia":"Section 19","remediation":"Set screen lock password on every device. Enable auto-lock after 5 minutes.","weight":7},
    {"id":11,"category":"Device Security","question":"If a laptop was stolen, could you remotely wipe it?","risk":"HIGH","popia":"Section 19","remediation":"Enable Microsoft Intune or Find My Device on all business laptops.","weight":7},
    {"id":12,"category":"Device Security","question":"Do all business computers have antivirus or endpoint protection?","risk":"HIGH","popia":"Section 19","remediation":"Enable Windows Defender (free, built into Windows) or install business antivirus.","weight":7},
    {"id":13,"category":"People & Awareness","question":"Have all staff been trained on how to spot phishing emails in the last 12 months?","risk":"HIGH","popia":"Section 19","remediation":"Run phishing awareness training. Free resources at knowbe4.com.","weight":8},
    {"id":14,"category":"People & Awareness","question":"Do you have a clear policy for how staff must handle client data?","risk":"HIGH","popia":"Section 18","remediation":"Write a one-page data handling policy. No client data to personal emails or drives.","weight":7},
    {"id":15,"category":"POPIA Compliance","question":"Have you appointed an Information Officer as required by POPIA?","risk":"CRITICAL","popia":"Section 55","remediation":"Appoint an Information Officer and register them with the Information Regulator at inforegulator.org.za. This is a legal requirement.","weight":10},
    {"id":16,"category":"POPIA Compliance","question":"Do you have a documented breach response plan so you can act immediately if personal data is compromised?","risk":"CRITICAL","popia":"Section 22","remediation":"Create a breach response plan. POPIA requires you to notify the Information Regulator and affected people as soon as reasonably possible after a breach.","weight":10},
    {"id":17,"category":"POPIA Compliance","question":"Do you get explicit consent before collecting client personal information?","risk":"HIGH","popia":"Section 11","remediation":"Add a consent clause to all client onboarding forms before collecting any data.","weight":8},
    {"id":18,"category":"POPIA Compliance","question":"Do you have a process to delete client data when it is no longer needed?","risk":"HIGH","popia":"Section 14","remediation":"Create a data retention policy. Delete or anonymise data no longer required.","weight":7},
    {"id":19,"category":"Incident Response","question":"Do you have an IT support contact or procedure for when things go wrong?","risk":"MEDIUM","popia":"Section 19","remediation":"Identify IT support before an incident happens. Have their number saved and ready.","weight":5},
    {"id":20,"category":"Incident Response","question":"Have you tested what would happen if ransomware locked all your files today?","risk":"HIGH","popia":"Section 19","remediation":"Run a tabletop exercise: if files were locked today, what would you do? Find the gaps.","weight":7},
]

INDUSTRIES = {
    "1": "Accounting & Financial Services",
    "2": "Healthcare & Medical Practice",
    "3": "Legal Practice",
    "4": "Retail & E-commerce",
    "5": "Construction & Engineering",
    "6": "Education & Training",
    "7": "Real Estate",
    "8": "Other Business",
}

LANGUAGES = {
    "1": "English",
    "2": "isiZulu",
    "3": "Sesotho",
    "4": "Afrikaans",
}

LANG_INSTRUCTIONS = {
    "English": "Write the entire report in clear simple English suitable for a non-technical business owner.",
    "isiZulu": "Bhala umbiko wonke ngesiZulu. Sebenzisa ulimi olulula lwansuku zonke oluzwisiswa ngumnikazi webhizinisi.",
    "Sesotho": "Ngola tlaleho yohle ka Sesotho. Sebedisa puo e bonolo ya letsatsi le letsatsi e utlwahalang ho mong'a kgwebo.",
    "Afrikaans": "Skryf die volledige verslag in eenvoudige Afrikaans geskik vir 'n nie-tegniese besigheidseienaar.",
}


def get_score(answers):
    total = sum(c["weight"] for c in SECURITY_CONTROLS)
    passed = sum(c["weight"] for c, a in zip(SECURITY_CONTROLS, answers) if a == "yes")
    score = int((passed / total) * 100)
    if score >= 85:
        return score, "LOW RISK"
    elif score >= 65:
        return score, "MEDIUM RISK"
    elif score >= 40:
        return score, "HIGH RISK"
    else:
        return score, "CRITICAL RISK"


def generate_report(prompt):
    """Call Claude and return only the text of the reply."""
    try:
        message = client.messages.create(
            model=MODEL,
            max_tokens=8000,
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.AuthenticationError:
        raise SystemExit("Your API key was rejected. Check ANTHROPIC_API_KEY in your .env file.")
    except anthropic.APIStatusError as e:
        raise SystemExit(f"Anthropic API error ({e.status_code}): {e.message}")
    except anthropic.APIConnectionError:
        raise SystemExit("Could not reach the Anthropic API. Check your internet connection.")

    # The reply can contain several blocks (e.g. thinking + text). Keep only the text.
    report = "".join(block.text for block in message.content if block.type == "text").strip()
    if not report:
        raise SystemExit("Claude returned no text. Please run the assessment again.")
    return report


def run():
    print("\n" + "=" * 65)
    print("   SECURECHECKS SA")
    print("   National SME Cyber Risk Platform")
    print("   Powered by Progress OpenEdge + Claude AI")
    print("   POPIA-Aligned | Built for South African Businesses")
    print("=" * 65)

    business = input("\nBusiness name: ").strip() or "Business"
    owner = input("Owner/Manager name: ").strip() or "Owner"

    print("\nSelect your industry:")
    for k, v in INDUSTRIES.items():
        print(f"  {k}. {v}")
    industry = INDUSTRIES.get(input("Enter number (1-8): ").strip(), "Business")

    print("\nSelect report language:")
    for k, v in LANGUAGES.items():
        print(f"  {k}. {v}")
    language = LANGUAGES.get(input("Enter number (1-4): ").strip(), "English")
    lang_instruction = LANG_INSTRUCTIONS[language]

    print(f"\n{'─' * 65}")
    print(f"Starting: {business} | {industry} | {language}")
    print("Answer each question with yes or no")
    print(f"{'─' * 65}\n")

    answers = []
    failed = []
    last_cat = ""

    for i, control in enumerate(SECURITY_CONTROLS):
        if control["category"] != last_cat:
            print(f"\n── {control['category']} ──")
            last_cat = control["category"]
        print(f"\n[{i + 1}/{len(SECURITY_CONTROLS)}] {control['question']}")
        while True:
            ans = input("   yes/no: ").strip().lower()
            if ans in ["yes", "no", "y", "n"]:
                ans = "yes" if ans in ["yes", "y"] else "no"
                break
            print("   Please type yes or no")
        answers.append(ans)
        if ans == "no":
            failed.append(control)

    score, rating = get_score(answers)
    passed_count = answers.count("yes")
    critical_fails = [c for c in failed if c["risk"] == "CRITICAL"]
    high_fails = [c for c in failed if c["risk"] == "HIGH"]
    today = datetime.datetime.now().strftime("%d %B %Y")

    failed_text = "\n".join([
        f"[{c['risk']} RISK | {c['popia']}] {c['question']}\nFix: {c['remediation']}"
        for c in failed
    ]) if failed else "All controls passed."

    prompt = f"""You are SecureCheck SA, a cybersecurity advisor for South African small and medium businesses.

You have completed a 20-point security assessment. All data below comes from the OpenEdge security controls database. Do not invent or change any risk levels, POPIA sections, or remediation steps.

ASSESSMENT DATA:
Business: {business}
Industry: {industry}
Owner: {owner}
Date: {today}
Security Score: {score}/100
Risk Rating: {rating}
Controls Passed: {passed_count}/20
Controls Failed: {len(failed)}/20
Critical Failures: {len(critical_fails)}
High Risk Failures: {len(high_fails)}

FAILED CONTROLS (from OpenEdge database - use exactly as provided):
{failed_text}

{lang_instruction}

Write a professional security assessment report with EXACTLY these sections:

# SECURECHECKS SA - SECURITY ASSESSMENT REPORT
**Business:** {business} | **Date:** {today} | **Score:** {score}/100 - {rating}

## Executive Summary
Two direct paragraphs. What the score means for this specific industry. How serious the risk is. Be honest.

## What You Are Doing Well
List every YES answer with a brief positive note. If nothing passed write "No controls are currently in place."

## CRITICAL - Fix These This Week
For each CRITICAL failure: explain the real-world consequence for a {industry}. Name the exact POPIA section. Give the specific fix with a time estimate.

## HIGH PRIORITY - Fix Within 30 Days
For each HIGH risk failure: same format.

## RECOMMENDED IMPROVEMENTS
For each MEDIUM risk: brief format. If there are none, write "No medium risk failures."

## Your POPIA Compliance Status
Specific paragraph for a {industry} in South Africa. Reference every POPIA section from their failures. State penalties reach R10 million or 10 years imprisonment. Name the Information Regulator of South Africa. Tell them to visit inforegulator.org.za.

## Your 30-Day Action Plan
Numbered priority list of 5 most important fixes with realistic time and cost estimates. Mark free options clearly.

## About SecureCheck SA
"All security controls, risk scores and POPIA references in this report are sourced from the SecureCheck SA database powered by Progress OpenEdge. Claude AI explains and communicates the findings - it does not generate or modify them. SecureCheck SA was built for the 2 million South African small businesses that cannot afford a cybersecurity consultant."

Write for a business owner not an IT person. No jargon. Be specific to their industry throughout. This report is guidance, not legal advice."""

    print(f"\n{'=' * 65}")
    print("   Generating your security report...")
    print(f"   Score: {score}/100 - {rating}")
    print(f"{'=' * 65}\n")

    report = generate_report(prompt)
    print(report)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_business = re.sub(r"[^A-Za-z0-9_-]", "_", business) or "business"
    filename = PROJECT_ROOT / f"report_{safe_business}_{ts}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("SECURECHECKS SA - SECURITY ASSESSMENT REPORT\n")
        f.write("=" * 65 + "\n\n")
        f.write(report)

    csv_file = PROJECT_ROOT / "assessment_log.csv"
    exists = csv_file.exists()
    with open(csv_file, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["Date", "Business", "Industry", "Owner", "Score", "Rating", "Failed", "Critical"])
        w.writerow([
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            business, industry, owner, score, rating, len(failed), len(critical_fails),
        ])

    print(f"\n{'=' * 65}")
    print(f"Report saved: {filename.name}")
    print(f"Logged to: {csv_file.name}")
    print(f"{'=' * 65}\n")


if __name__ == "__main__":
    run()