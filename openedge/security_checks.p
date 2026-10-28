/*------------------------------------------------------------------------
    SecureCheck SA - OpenEdge Security Controls Database
    This is the trusted data source for all security controls.
    AI explains these findings. AI never invents risk scores.
    Author: Mohau Bengo | AIE Johannesburg | Hackathon 2026
------------------------------------------------------------------------*/

DEFINE TEMP-TABLE ttSecurityControl NO-UNDO
    FIELD ControlID      AS INTEGER
    FIELD Category       AS CHARACTER FORMAT "X(30)"
    FIELD Question       AS CHARACTER FORMAT "X(80)"
    FIELD RiskLevel      AS CHARACTER FORMAT "X(10)"
    FIELD POPIASection   AS CHARACTER FORMAT "X(15)"
    FIELD Weight         AS INTEGER
    FIELD Remediation    AS CHARACTER FORMAT "X(200)".

DEFINE TEMP-TABLE ttIndustry NO-UNDO
    FIELD IndustryID     AS INTEGER
    FIELD IndustryName   AS CHARACTER FORMAT "X(40)"
    FIELD HighRiskData   AS LOGICAL.

/* Industries */
CREATE ttIndustry. ASSIGN ttIndustry.IndustryID=1 ttIndustry.IndustryName="Accounting & Financial Services" ttIndustry.HighRiskData=TRUE.
CREATE ttIndustry. ASSIGN ttIndustry.IndustryID=2 ttIndustry.IndustryName="Healthcare & Medical Practice" ttIndustry.HighRiskData=TRUE.
CREATE ttIndustry. ASSIGN ttIndustry.IndustryID=3 ttIndustry.IndustryName="Legal Practice" ttIndustry.HighRiskData=TRUE.
CREATE ttIndustry. ASSIGN ttIndustry.IndustryID=4 ttIndustry.IndustryName="Retail & E-commerce" ttIndustry.HighRiskData=FALSE.
CREATE ttIndustry. ASSIGN ttIndustry.IndustryID=5 ttIndustry.IndustryName="Construction & Engineering" ttIndustry.HighRiskData=FALSE.
CREATE ttIndustry. ASSIGN ttIndustry.IndustryID=6 ttIndustry.IndustryName="Education & Training" ttIndustry.HighRiskData=TRUE.
CREATE ttIndustry. ASSIGN ttIndustry.IndustryID=7 ttIndustry.IndustryName="Real Estate" ttIndustry.HighRiskData=FALSE.
CREATE ttIndustry. ASSIGN ttIndustry.IndustryID=8 ttIndustry.IndustryName="Other Business" ttIndustry.HighRiskData=FALSE.

/* Security Controls */
CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=1 ttSecurityControl.Category="Identity & Access"
       ttSecurityControl.Question="Do all staff accounts have MFA enabled?"
       ttSecurityControl.RiskLevel="CRITICAL" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=10
       ttSecurityControl.Remediation="Enable MFA on every account. Use Microsoft Authenticator. Takes 10 min per user.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=2 ttSecurityControl.Category="Identity & Access"
       ttSecurityControl.Question="Does every staff member have their own unique login?"
       ttSecurityControl.RiskLevel="CRITICAL" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=10
       ttSecurityControl.Remediation="Create individual accounts for each person. Use Bitwarden free password manager.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=3 ttSecurityControl.Category="Identity & Access"
       ttSecurityControl.Question="Do you review who has access to your systems every 6 months?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=8
       ttSecurityControl.Remediation="Review and remove access for anyone who left or changed roles.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=4 ttSecurityControl.Category="Data Protection"
       ttSecurityControl.Question="Is all client data stored in encrypted cloud storage?"
       ttSecurityControl.RiskLevel="CRITICAL" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=10
       ttSecurityControl.Remediation="Move to Microsoft OneDrive or Azure Blob Storage. Stop using USB drives.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=5 ttSecurityControl.Category="Data Protection"
       ttSecurityControl.Question="Are automated backups running at least daily?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=8
       ttSecurityControl.Remediation="Enable Microsoft 365 backup or Azure Backup. Test restore monthly.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=6 ttSecurityControl.Category="Data Protection"
       ttSecurityControl.Question="Do you know exactly where all your client data is stored?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 14"
       ttSecurityControl.Weight=8
       ttSecurityControl.Remediation="Create a data inventory listing every system holding client data.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=7 ttSecurityControl.Category="Network Security"
       ttSecurityControl.Question="Is business WiFi protected with WPA2 or WPA3 encryption?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=7
       ttSecurityControl.Remediation="Log into your router and enable WPA3. Change the default password.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=8 ttSecurityControl.Category="Network Security"
       ttSecurityControl.Question="Do you have a separate WiFi for guests and personal devices?"
       ttSecurityControl.RiskLevel="MEDIUM" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=5
       ttSecurityControl.Remediation="Create a guest network on your router separate from business devices.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=9 ttSecurityControl.Category="Network Security"
       ttSecurityControl.Question="Are all devices running up-to-date software and patches?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=8
       ttSecurityControl.Remediation="Enable automatic updates on all Windows PCs and mobile devices.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=10 ttSecurityControl.Category="Device Security"
       ttSecurityControl.Question="Are all business laptops protected with a password or PIN?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=7
       ttSecurityControl.Remediation="Set screen lock password on every device. Enable auto-lock after 5 minutes.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=11 ttSecurityControl.Category="Device Security"
       ttSecurityControl.Question="Can you remotely wipe a stolen business laptop?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=7
       ttSecurityControl.Remediation="Enable Microsoft Intune or Find My Device on all business laptops.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=12 ttSecurityControl.Category="Device Security"
       ttSecurityControl.Question="Do all business computers have antivirus or endpoint protection?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=7
       ttSecurityControl.Remediation="Enable Windows Defender (free) or install business antivirus. Run weekly scans.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=13 ttSecurityControl.Category="People & Awareness"
       ttSecurityControl.Question="Have all staff been trained on phishing in the last 12 months?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=8
       ttSecurityControl.Remediation="Run phishing awareness training. Free resources at knowbe4.com.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=14 ttSecurityControl.Category="People & Awareness"
       ttSecurityControl.Question="Do you have a clear policy for how staff handle client data?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 18"
       ttSecurityControl.Weight=7
       ttSecurityControl.Remediation="Write a one-page data handling policy. No client data to personal emails.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=15 ttSecurityControl.Category="POPIA Compliance"
       ttSecurityControl.Question="Have you appointed an Information Officer as required by POPIA?"
       ttSecurityControl.RiskLevel="CRITICAL" ttSecurityControl.POPIASection="Section 55"
       ttSecurityControl.Weight=10
       ttSecurityControl.Remediation="Appoint and register an Information Officer at justice.gov.za immediately.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=16 ttSecurityControl.Category="POPIA Compliance"
       ttSecurityControl.Question="Do you have a breach response plan to act within 72 hours?"
       ttSecurityControl.RiskLevel="CRITICAL" ttSecurityControl.POPIASection="Section 22"
       ttSecurityControl.Weight=10
       ttSecurityControl.Remediation="Create a breach response plan. POPIA requires notification within 72 hours.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=17 ttSecurityControl.Category="POPIA Compliance"
       ttSecurityControl.Question="Do you get explicit consent before collecting client personal information?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 11"
       ttSecurityControl.Weight=8
       ttSecurityControl.Remediation="Add a consent clause to all client onboarding forms.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=18 ttSecurityControl.Category="POPIA Compliance"
       ttSecurityControl.Question="Do you have a process to delete client data when no longer needed?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 14"
       ttSecurityControl.Weight=7
       ttSecurityControl.Remediation="Create a data retention policy. Delete data that is no longer required.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=19 ttSecurityControl.Category="Incident Response"
       ttSecurityControl.Question="Do you have an IT support contact for when things go wrong?"
       ttSecurityControl.RiskLevel="MEDIUM" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=5
       ttSecurityControl.Remediation="Identify IT support before an incident. Have their number saved.".

CREATE ttSecurityControl.
ASSIGN ttSecurityControl.ControlID=20 ttSecurityControl.Category="Incident Response"
       ttSecurityControl.Question="Have you tested your response if ransomware locked all your files?"
       ttSecurityControl.RiskLevel="HIGH" ttSecurityControl.POPIASection="Section 19"
       ttSecurityControl.Weight=7
       ttSecurityControl.Remediation="Run a tabletop exercise: if files were locked today, what would you do?".

FOR EACH ttSecurityControl BY ttSecurityControl.ControlID:
    DISPLAY
        ttSecurityControl.ControlID    LABEL "ID"
        ttSecurityControl.Category     LABEL "Category"
        ttSecurityControl.RiskLevel    LABEL "Risk"
        ttSecurityControl.POPIASection LABEL "POPIA"
        ttSecurityControl.Weight       LABEL "Weight"
    WITH FRAME controls DOWN.
END.

MESSAGE "SecureCheck SA: 20 controls loaded. 7 categories. POPIA-aligned."
    VIEW-AS ALERT-BOX INFORMATION TITLE "SecureCheck SA - OpenEdge".