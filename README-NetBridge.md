# NetBridge

**An offline-first, local-network digital payment simulation prototype**

NetBridge is an educational prototype that explores how a wallet-style payment experience could work across nearby devices, including QR-based payment requests, device trust, authenticator-based verification, and offline authorization workflows.

> [!IMPORTANT]
> **NetBridge is a simulation project, not a real payment application.** Real payments, bank transfers, UPI settlement, and financial-network integrations are not enabled. The application reports `simulation_only` and `real_payments_enabled: false`. Do not use it to store real money, credentials, or sensitive financial information.

## Author

**Bidyadhar Jena**

## Project goals

NetBridge is designed to demonstrate and help explore:

- A customer wallet and merchant-facing interface.
- Local Flask APIs backed by SQLite.
- QR-based merchant payment requests and validation.
- Offline payment request and customer-authorization flows.
- Cryptographic device identity and trusted-device registration/revocation.
- Time-based one-time password (TOTP) authenticator enrollment and verification.
- Offline receipt handling, ledger records, and spending controls.
- Progressive Web App (PWA) assets and service-worker caching for the application shell.
- Automated Python and JavaScript tests.

## Features

### Customer and merchant experience
- Separate customer and merchant web interfaces.
- Wallet balance and transaction-history endpoints.
- Merchant payment-request creation and QR workflows.
- Local-network discovery helpers for NetBridge services.

### Authentication and device trust
- Wallet PIN verification.
- TOTP authenticator support compatible with Google Authenticator and other RFC 6238 applications.
- Device identity and signed-message helpers.
- Trusted-device registration, listing, and revocation.

### Offline workflow
- Versioned offline payment protocol.
- Signed payment requests and customer authorization.
- QR payload creation and parsing.
- Receipt validation and offline ledger support.
- Offline spending-limit controls.

### Local-first application shell
- Flask application served locally.
- SQLite persistence for demo data.
- PWA manifest and service worker.
- Browser assets and QR libraries are included in the repository.

Feature availability and behavior are defined by the current implementation. This README does not imply that every workflow provides real-world payment settlement.

## Technology stack

| Area | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite |
| Security and cryptography | Python standard library, `cryptography` |
| QR generation | `qrcode`, Pillow |
| Network utilities | `psutil`, Python networking libraries |
| Frontend | HTML, CSS, JavaScript |
| PWA | Web App Manifest, Service Worker |
| JavaScript checks | Node.js |
| Python tests | pytest |

## Repository structure

```text
NetBridge/
├── app.py                       # Flask application and API routes
├── database.py                  # SQLite database and wallet operations
├── transactions.py              # Transaction processing logic
├── security.py                  # Input and payment validation helpers
├── authenticator/               # TOTP, identity, QR, and challenge modules
├── offline/                     # Offline protocol, QR, receipt, ledger,
│                                # and spending-control modules
├── network/                     # Local-network service and discovery
├── templates/                   # Customer and merchant HTML pages
├── static/                      # CSS, JavaScript, PWA assets, and icons
│   └── vendor/                   # Third-party browser libraries and notices
├── tests/                       # Python and JavaScript tests
├── docs/                        # Project documentation
├── scripts/                     # Local setup helpers
├── data/                        # Runtime data placeholder
├── requirements.txt             # Runtime Python dependencies
├── requirements-dev.txt         # Development/test dependencies
├── package.json                 # JavaScript test scripts
└── LICENSE                      # MIT License
```

## Requirements

Install the following before running the project:

- Python **3.10 or newer**.
- `pip`.
- Node.js **20 or newer** (only required for the JavaScript checks).
- A modern browser.

## Installation

### 1. Download or clone the repository

```bash
git clone <repository-url>
cd NetBridge
```

If you downloaded the source as a ZIP file, extract it and open the project folder in your terminal or VS Code.

### 2. Create a virtual environment

**Windows (PowerShell):**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**

```bat
py -m venv .venv
.venv\Scripts\activate.bat
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

For normal use:

```bash
python -m pip install -r requirements.txt
```

For development and Python testing:

```bash
python -m pip install -r requirements-dev.txt
```

### 4. Start NetBridge

```bash
python app.py
```

By default, the Flask application listens locally at:

```text
http://127.0.0.1:5001
```

Open that address in your browser.

The application starts in simulation mode. When launched through `app.py`, the current implementation restores the demo wallets and clears demo transaction history and authenticator enrollments for that run. Do not treat the local SQLite database as durable financial storage.

## Demo accounts

The project initializes fictional demo wallets for local testing:

| Role | Wallet ID | Demo PIN |
|---|---|---|
| Customer | `CUSTOMER001` | `1234` |
| Customer / receiver | `CUSTOMER002` | `4321` |
| Merchant | `MERCHANT001` | `5678` |

These credentials are public test fixtures embedded in the source code. **Never reuse them as real credentials or expose a development instance to an untrusted network.**

## Application pages and API

### Main pages

| Path | Purpose |
|---|---|
| `/` | Main customer interface |
| `/customer` | Customer interface |
| `/merchant` | Merchant interface |
| `/far-wallet/customer2` | Additional demo wallet interface |
| `/service-worker.js` | Service worker endpoint |

### API areas

The Flask API includes endpoints for:

- Health/status reporting: `/api/health`
- Wallet lookup, balance, and transaction history: `/api/wallets/...`
- Authenticator enrollment and verification: `/api/authenticator/...`
- Device identity and trusted-device management: `/api/auth/...`, `/api/devices/...`
- Merchant QR and payment requests: `/api/merchant/...`
- Transaction creation and processing: `/api/transactions/...`
- Offline payment requests, authorization, receipts, ledger, and spending: `/api/offline/...`

For exact request formats, validation rules, and response fields, refer to the route implementations in `app.py` and the corresponding modules.

The legacy `/api/pay` endpoint is intentionally disabled and returns HTTP `410`.

## Configuration

The application supports these environment variables:

| Variable | Default | Description |
|---|---|---|
| `NETBRIDGE_HOST` | `127.0.0.1` without TLS; `0.0.0.0` when TLS files are available | Interface on which Flask listens |
| `NETBRIDGE_PORT` | `5001` | Flask application port |
| `NETBRIDGE_TLS_CERT` | `netbridge-lan-cert.pem` in the project directory | TLS certificate path |
| `NETBRIDGE_TLS_KEY` | `netbridge-lan-key.pem` in the project directory | TLS private-key path |

The application refuses non-local hosting without a certificate and key. For local HTTPS certificate setup on Windows, see `scripts/setup_local_https.ps1`.

**Network caution:** Binding to `0.0.0.0` makes the service reachable through available network interfaces. Only do this on a network you control, use a trusted HTTPS certificate, and configure firewall access deliberately. Local-network discovery and the auxiliary network service are intended for controlled development/testing environments.

## Running tests

### Python tests

Install development dependencies, then run:

```bash
python -m pytest
```

### JavaScript tests

From the repository root:

```bash
npm test
```

The npm test script runs the JavaScript receipt-code and offline-TOTP checks.

Tests are intended to validate prototype behavior. Passing tests do not constitute a security audit, compliance assessment, or approval for production financial use.

## Security and responsible use

NetBridge contains security-related demonstration mechanisms, but it has not been established as a production-grade financial system.

- Real payment processing and settlement are disabled.
- Demo wallet credentials are intentionally predictable and must remain test-only.
- Do not deploy this prototype publicly or connect it to real financial accounts.
- Do not place real personal, banking, payment-card, or authentication data in the application.
- Protect TLS private keys and local database files.
- Review dependencies and third-party notices before redistribution.
- Obtain an independent security review before adapting any part of this project for a real service.

## Known project boundaries

- The current application is a local/demo prototype.
- The payment workflows simulate application behavior; they do not move real funds.
- Demo wallet and authenticator state is reset when the application is started with `python app.py`.
- Local-network functionality depends on the host network, firewall, and certificate configuration.
- No claim of regulatory, banking, UPI, or payment-network certification is made.

## Contributing

Contributions, bug reports, and suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Keep changes focused and add or update tests where appropriate.
4. Run the Python and JavaScript test suites.
5. Submit a pull request describing the change and its testing.

Please avoid committing virtual environments, local databases, private keys, certificates containing private material, secrets, or personal data.

## License

This project is licensed under the **MIT License**. See the [`LICENSE`](LICENSE) file for details.

Third-party components bundled in `static/vendor/` may be distributed under their own licenses. Refer to the accompanying vendor license notices and the relevant upstream projects.

---

**NetBridge** — an educational exploration of offline-first, local-network payment workflows.

**Author:** Bidyadhar Jena
