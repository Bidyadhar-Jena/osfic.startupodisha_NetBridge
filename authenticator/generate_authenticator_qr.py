# generate_authenticator_qr.py

import qrcode
import pyotp

# NetBridge demo account
account_name = "CUSTOMER001"
issuer = "NetBridge"

# Generate a new Authenticator secret
secret = pyotp.random_base32()

# Generate Google Authenticator provisioning URI
totp = pyotp.TOTP(secret)

provisioning_uri = totp.provisioning_uri(
    name=account_name,
    issuer_name=issuer
)

# Generate QR code
qr = qrcode.make(provisioning_uri)
qr.save("netbridge_authenticator_qr.png")

# Save secret locally for verification
with open("netbridge_totp_secret.txt", "w", encoding="utf-8") as file:
    file.write(secret)

print("================================")
print(" NetBridge Authenticator Setup")
print("================================")
print("QR generated successfully!")
print("File: netbridge_authenticator_qr.png")
print("Account:", account_name)
print("Issuer:", issuer)
print("Scan the QR using Google Authenticator.")
