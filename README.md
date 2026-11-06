# Cybersecurity Awareness

**Student:** Manish Malviya  
**College:** UIT RGPV, Bhopal  
**Internship:** EWB Edutech Private Limited — AI-Powered Cybersecurity Internship  
**Project type:** Python educational mini project

## 1. Project overview

This command-line mini project demonstrates three basic cybersecurity ideas:

1. **Password hygiene:** gives simple strength feedback for a test password.
2. **Phishing awareness:** highlights wording that may deserve scrutiny in a suspicious message.
3. **Sign-in log triage:** reads a small synthetic CSV log and highlights simple patterns for review.

The project is designed for learning and uses only Python's standard library.

## 2. Important scope and safety

- Use only fictional/sample messages and test passwords.
- Never type your real password, OTP, identity information or another person's private data.
- The password checker evaluates input locally and does not save it.
- The log file is synthetic training data.
- The program does not scan public systems, send messages, access accounts or connect to the internet.
- A warning flag is not proof of an attack. An IP address does not identify a person.
- This is a basic educational demonstration, not production security software.

## 3. Requirements

- Python 3.10 or newer recommended
- No third-party packages required

Check Python:

```bash
python --version
```

## 4. Files

```text
cybersecurity-mini-project/
├── main.py
├── sample_login_log.csv
├── test_main.py
├── README.md
├── requirements.txt
└── .gitignore
```

## 5. Run the project

Open a terminal in this folder:

```bash
python main.py
```

Choose:
- `1` to check a made-up test password
- `2` to analyse a fictional suspicious message
- `3` to analyse the sample synthetic sign-in log
- `4` to exit

On some systems, use `python3 main.py`.

## 6. Sample message for option 2

You can paste this fictional example:

```text
FINAL WARNING: Your scholarship expires in 20 minutes.
Verify your account immediately and enter your password and OTP.
Do not contact the college office.
```

Expected behaviour: the tool should flag urgency, sensitive-information wording and the instruction not to contact the organisation. It does not prove that a sender or website is malicious.

## 7. Test the project

Run:

```bash
python -m unittest -v
```

The tests use dummy inputs only.

## 8. Screenshots to capture for your submission

Run the program and capture your own screenshots showing:

1. The main menu.
2. A password-strength result using a made-up test password (do not show a real password).
3. The phishing warning signs for the fictional sample message.
4. The synthetic login-log analysis.
5. The unit-test result after running `python -m unittest -v`.

Save screenshots in a folder named `screenshots/`. Do not include personal account pages, real credentials, OTPs or identity documents.

## 9. Suggested GitHub repository description

`A Python-based cybersecurity awareness demonstrating password hygiene, phishing red-flag analysis, and synthetic login-log triage.`

## 10. Suggested repository topics

`python`, `cybersecurity`, `phishing-awareness`, `password-security`, `log-analysis`, `beginner-project`
