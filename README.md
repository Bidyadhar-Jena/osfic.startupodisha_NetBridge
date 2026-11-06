# NetBridge

NetBridge is an educational prototype for simulated payments in limited-connectivity settings. It is not a UPI client, bank integration, payment processor, or production wallet. It does not move real money.

## Run locally (Windows)

1. Install Python 3.11+ and create a virtual environment: `py -m venv .venv`, then `.venv\Scripts\Activate.ps1`.
2. Install dependencies: `python -m pip install -r requirements-dev.txt`.
3. For local HTTPS, install [mkcert](https://github.com/FiloSottile/mkcert), then run `powershell -ExecutionPolicy Bypass -File .\scripts\setup_local_https.ps1`. The generated certificate and private key are ignored by Git. Android camera access may also require trusting the local mkcert CA on the phone.
4. Start the server with `python app.py`. Open the URL printed in the terminal.

The project includes customer and merchant demo pages. The prototype demonstrates a customer QR request, authenticator verification, an offline receipt/handoff code, and merchant-side recording. Network synchronization and far-payment flows are simulations; they do not guarantee delivery of real funds.

## Demo data and authenticator

This prototype may initialize or reset demo wallet, transaction, or authenticator state when the server starts. Use only test data and do not enter real credentials or secrets. Runtime identity and database files are local and excluded from Git.

## Tests

Run Python checks with `python -m pytest`. JavaScript tests require Node.js and can be run individually with `node tests/test_manual_receipt_code.js` and `node tests/test_offline_totp.js`.

## GitHub safety

`.gitignore` excludes TLS certificates and private keys, local databases, runtime identity JSON, environment files, caches, and generated artifacts. Review `git status` and `git diff --cached` before publishing. Never commit real keys, authenticator setup secrets, customer data, or production credentials.

See [`docs/project-layout.md`](docs/project-layout.md) for the folder map.
