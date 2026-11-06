import tempfile
import unittest
from pathlib import Path

from main import check_password_strength, analyse_message, analyse_login_log


class CybersecurityToolkitTests(unittest.TestCase):
    def test_password_strength_returns_feedback(self):
        level, tips = check_password_strength("Test")
        self.assertIn(level, {"Weak", "Moderate", "Strong"})
        self.assertIsInstance(tips, list)

    def test_password_strength_strong_sample(self):
        level, tips = check_password_strength("BlueRiver!2026Safe")
        self.assertEqual(level, "Strong")
        self.assertEqual(tips, [])

    def test_message_analyser_flags_otp_and_urgency(self):
        flags = analyse_message("FINAL WARNING: enter your password and OTP now")
        combined = " ".join(flags).lower()
        self.assertIn("otp", combined)
        self.assertTrue(any("pressure" in f.lower() for f in flags))

    def test_log_analyser_detects_synthetic_pattern(self):
        sample = Path(__file__).parent / "sample_login_log.csv"
        result = analyse_login_log(str(sample))
        combined = " ".join(result).lower()
        self.assertIn("failed password attempts", combined)
        self.assertIn("session creation", combined)


if __name__ == "__main__":
    unittest.main()
