# Project layout

- `app.py`, `database.py`, `transactions.py`, `security.py`: Flask app and core demo services.
- `authenticator/`: authenticator enrollment and verification.
- `offline/`: offline payment protocol, QR helpers, receipt validation, spending controls, and ledger.
- `network/`: local network services and device discovery.
- `templates/` and `static/`: customer/merchant pages and browser assets. Browser offline assets remain under `static/` because the pages and service worker load them from `/static/`.
- `tests/`: Python and JavaScript checks.
- `data/`: runtime state; local databases and identity files are ignored by Git.
- `scripts/`: local developer setup helpers.
