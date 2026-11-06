
import pyotp
from pathlib import Path

secret_file = Path("netbridge_totp_secret.txt")

if not secret_file.exists():
    print("Authenticator secret file not found!")
    raise SystemExit

secret = secret_file.read_text(encoding="utf-8").strip()
totp = pyotp.TOTP(secret)

code = input("Enter the 6-digit Google Authenticator code: ").strip()

if not code.isdigit() or len(code) != 6:
    print("Invalid code format.")
elif totp.verify(code, valid_window=1):
    print("Authenticator verification successful!")
else:
    print("Incorrect or expired code.")
