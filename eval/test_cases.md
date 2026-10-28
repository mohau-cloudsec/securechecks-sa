# SecureCheck SA — Test Cases

## Test 1 — Critical Risk (all no)
Answer NO to all 20. Industry: Accounting. Language: English.
Expected: Score 0/100. CRITICAL RISK. All POPIA failures listed. R10m penalty warning.

## Test 2 — Low Risk (all yes)
Answer YES to all 20. Industry: Retail. Language: English.
Expected: Score 100/100. LOW RISK. Positive summary.

## Test 3 — Mixed
YES to MFA, backups, antivirus only. NO to rest. Industry: Healthcare.
Expected: Score ~35/100. CRITICAL RISK. Healthcare POPIA context.

## Test 4 — Invalid Input (failure case)
Type "maybe" on question 3.
Expected: System asks again. Does not crash.

## Test 5 — isiZulu
Mixed answers. Language: isiZulu. Industry: Legal.
Expected: Full report in isiZulu. POPIA sections correct.

## Test 6 — POPIA Only Failures
YES to all except questions 15-18. Industry: Accounting.
Expected: Score ~65/100. Information Officer top priority.

## Test 7 — Single Critical Failure
YES to all except question 15. Industry: Legal.
Expected: Score ~90/100. Focused Section 55 warning.