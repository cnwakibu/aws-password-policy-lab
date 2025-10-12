# AWS Password Policy Lab 🔐

## Problem
Organizations need strong password policies to protect accounts and meet compliance standards (SOC 2 CC6.6, NIST 800-53 IA-5).

## Solution
I ran a Python script to audit my AWS IAM password policies.  
The script checked:
- Password length  
- Complexity requirements  
- Reuse restrictions  
- Minimum & maximum password age  

It automatically generated JSON and CSV reports with results.

## Results
❌ First run = 0% compliance (IAM user didn’t have permissions)  
✅ After fixing permissions, compliance score + recommendations displayed  

## Evidence
- JSON report (`/evidence/password-policy-report.json`)  
- CSV report (`/evidence/password-policy-report.csv`)  
- Screenshot of compliance score  

## Key Takeaway
Compliance isn’t just checklists — it can be automated, measurable, and audit-ready.  

## Framework Tie-In
- **SOC 2 CC6.6** — Logical access security measures  
- **NIST 800-53 IA-5** — Authenticator management  

## Next Steps
- Extend script to check for password expiration policy  
- Integrate results into AWS Config for continuous compliance  

## Attribution
The Python script in the `/scripts` folder was originally provided by AJ Yawn for educational purposes.  
I used it to run the compliance check, generate evidence and document results as part of my hands-on learning.

