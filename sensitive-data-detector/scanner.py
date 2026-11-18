print("=" * 55)
print("          SENSITIVE DATA LEAK DETECTOR")
print("=" * 55)


print("-" * 55)
print(" Status : RUNNING")
print("-" * 55)

import os

TEST_FOLDER = "test_files"

files = os.listdir(TEST_FOLDER)

print("\nFiles available for scanning:")
print(files)

for file in files:
    file_path = os.path.join(TEST_FOLDER, file)

    with open(file_path, "r") as f:
        content = f.read()

    print("\nScanning file:", file)
    print(content)

import re

email_pattern = r'[\w.-]+@[\w.-]+\.\w+'

emails = re.findall(email_pattern, content)
risk_score = 0

if emails:
    print("⚠️ Email addresses found:", emails)
    risk_score += len(emails)
else:
    print("✅ No email addresses found.")

api_pattern = r'API_KEY\s*[:=]\s*\S+'

api_keys = re.findall(api_pattern, content)

if api_keys:
    print("WARNING: Possible API key found:", api_keys)
    risk_score += 3
else:
    print("No API key pattern found.")

password_pattern = r'password\s*[:=]\s*\S+'

passwords = re.findall(password_pattern, content, re.IGNORECASE)

if passwords:
    print("WARNING: Possible password found:", passwords)
    risk_score += 3
else:
    print("No password pattern found.")

print("\n" + "=" * 40)
print("          SCAN SUMMARY")
print("=" * 40)

print("Total Risk Score:", risk_score)

if risk_score == 0:
    print("Risk Level: SAHI H KOI NAHI")
elif risk_score <= 3:
    print("Risk Level: DIKKT HAI BHAI")
else:
    print("Risk Level: TURANT ACTION LE BHAI, BHOT JYADA DIKKT HAI")

print("=" * 40)
