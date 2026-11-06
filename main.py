"""
Cybersecurity Awareness Toolkit
Educational mini project for EWB Cybersecurity Internship.

This program works only with user-entered text and a synthetic CSV log.
It does not connect to the internet, scan systems, collect credentials, or
store passwords. Do not enter real passwords or personal information.
"""

import csv
import getpass
import re
from pathlib import Path

SUSPICIOUS_PHRASES = [
    "urgent", "final warning", "expires", "act immediately",
    "verify your account", "password", "otp", "one-time password",
    "gift card", "do not contact", "identity card", "click here"
]

def check_password_strength(password: str) -> tuple[str, list[str]]:
    """Evaluate a password locally; never save or print the supplied password."""
    suggestions = []
    score = 0

    if len(password) >= 12:
        score += 1
    else:
        suggestions.append("Use at least 12 characters.")

    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Mix uppercase and lowercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Include at least one number.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        suggestions.append("Include at least one special character.")

    common = {"password", "password123", "123456789", "qwerty123"}
    if password.lower() in common:
        score = 0
        suggestions.append("Avoid common or easily guessed passwords.")

    if score <= 1:
        level = "Weak"
    elif score <= 3:
        level = "Moderate"
    else:
        level = "Strong"

    return level, suggestions


def analyse_message(message: str) -> list[str]:
    """Return possible phishing warning signs; this is not a verdict."""
    text = message.lower()
    flags = []

    phrase_matches = [phrase for phrase in SUSPICIOUS_PHRASES if phrase in text]
    if phrase_matches:
        flags.append("Pressure or sensitive-information wording: " + ", ".join(phrase_matches))

    if re.search(r"https?://", text):
        flags.append("Contains a web link. Verify the destination independently; do not click it just to inspect it.")

    if re.search(r"\b(within \d+ minutes?|in \d+ minutes?|today only|limited time)\b", text):
        flags.append("Uses a short deadline or scarcity pressure.")

    if "reply-to" in text:
        flags.append("Mentions a Reply-To address; compare it with the organisation's independently verified address.")

    if any(term in text for term in ["send your", "share your", "enter your", "provide your"]):
        flags.append("Appears to request information. Never send passwords or OTPs in response to an unexpected message.")

    if not flags:
        flags.append("No listed indicator was detected. This does NOT prove the message is safe.")

    return flags


def analyse_login_log(csv_path: str) -> list[str]:
    """Analyse a small CSV with columns: timestamp,user,source_ip,event,result."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {csv_path}")

    events = []
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"timestamp", "user", "source_ip", "event", "result"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError("CSV must contain: timestamp,user,source_ip,event,result")
        events = list(reader)

    messages = []
    failed_by_ip = {}
    success_ips = set()
    denied_mfa = set()
    approved_mfa = set()
    session_ips = set()

    for row in events:
        ip = row["source_ip"].strip()
        event = row["event"].strip().lower()
        result = row["result"].strip().lower()

        if event == "password" and result == "failed":
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1
        elif event == "password" and result == "success":
            success_ips.add(ip)
        elif event == "mfa" and result == "denied":
            denied_mfa.add(ip)
        elif event == "mfa" and result == "approved":
            approved_mfa.add(ip)
        elif event == "session" and result == "created":
            session_ips.add(ip)

    for ip, count in failed_by_ip.items():
        if count >= 2:
            messages.append(f"{count} failed password attempts recorded from {ip}.")

    for ip in success_ips:
        if ip in approved_mfa and ip in session_ips:
            messages.append(
                f"Password success, MFA approval and session creation are recorded for {ip}. "
                "Review whether the sign-in was expected."
            )
        elif ip in denied_mfa:
            messages.append(f"MFA denial was recorded for {ip}; investigate the surrounding events.")

    if not messages:
        messages.append("No pattern covered by this simple rule set was detected.")

    messages.append(
        "Reminder: an IP address alone does not identify a person or prove malicious activity. "
        "Correlate with authorised device, identity-provider and user-confirmation evidence."
    )
    return messages


def main():
    while True:
        print("\n=== CYBERSECURITY AWARENESS TOOLKIT ===")
        print("1. Check password strength")
        print("2. Analyse a suspicious message")
        print("3. Analyse the supplied synthetic login log")
        print("4. Exit")
        choice = input("Choose an option (1-4): ").strip()

        if choice == "1":
            print("Enter a test password only. Do NOT enter a real password.")
            password = getpass.getpass("Test password: ")
            level, tips = check_password_strength(password)
            print(f"Estimated strength: {level}")
            for tip in tips:
                print("- " + tip)
            print("Privacy: the entered text is not saved by this program.")
            password = None

        elif choice == "2":
            message = input("Paste fictional/sample message text: ")
            print("\nPossible warning signs:")
            for flag in analyse_message(message):
                print("- " + flag)
            print("This is a basic educational checker, not a definitive phishing detector.")

        elif choice == "3":
            default_file = Path(__file__).parent / "sample_login_log.csv"
            file_name = input(f"CSV path (press Enter for {default_file.name}): ").strip()
            path = file_name if file_name else str(default_file)
            try:
                for item in analyse_login_log(path):
                    print("- " + item)
            except (FileNotFoundError, ValueError) as error:
                print("Could not analyse log:", error)

        elif choice == "4":
            print("Thank you. Stay alert and protect your accounts.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3 or 4.")


if __name__ == "__main__":
    main()
