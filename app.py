import base64
import io
import json
import logging
import os
from pathlib import Path
import secrets
import time
from decimal import Decimal, InvalidOperation
import qrcode
from flask import Flask, jsonify, render_template, request, send_from_directory

from authenticator.qr import generate_qr_code, generate_qr_matrix
from authenticator.totp import get_provisioning_uri
from authenticator.totp_store import (
    initialize_totp_storage,
    reset_totp_enrollments,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    is_totp_enabled,
    get_totp_secret,
    verify_and_consume_totp,
    verify_totp_for_reconnect,
)
from authenticator.identity import get_or_create_identity
from authenticator.challenge import ChallengeManager

from offline.offline_protocol import (
    create_payment_request as create_offline_payment_request,
    verify_payment_request,
    create_customer_authorization,
    verify_customer_authorization,
    calculate_digest,
)

from offline.offline_qr import create_qr_payload, parse_qr_payload
from offline.offline_ledger import initialize_ledger, list_offline_payments
from offline.offline_receipt import validate_payment_receipt

from offline.offline_spending_control import (
    record_authorization_with_spending_limits,
    get_customer_offline_spending,
)

from database import (
    initialize_database,
    get_connection,
    verify_wallet_pin,
    get_wallet,
    get_wallet_balance,
    reset_demo_wallets_and_history,
    process_demo_far_payment,
    register_trusted_device,
    get_trusted_device,
    is_device_trusted,
    list_trusted_devices,
    revoke_trusted_device,
    get_transaction_history,
    create_payment_request,
    get_payment_request,
    list_payment_requests,
    update_payment_request_status,
    record_offline_qr_receipt,
    list_offline_qr_receipts,
)

from transactions import create_transaction, process_transaction
from security import validate_pin


# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)
APP_SESSION_ID = secrets.token_urlsafe(24)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("NetBridge")

initialize_database()
initialize_totp_storage()
initialize_ledger()

challenge_manager = ChallengeManager()

REAL_PAYMENTS_ENABLED = False

MAX_PAYMENT_PAISE = 500_000

MAX_QR_AMOUNT_RUPEES = Decimal("5000.00")


# ============================================================
# COMMON HELPERS
# ============================================================

def error_response(message, status_code=400, **extra):

    response = {
        "success": False,
        "status": "error",
        "error": message,
        "real_payments_enabled": REAL_PAYMENTS_ENABLED,
    }

    response.update(extra)

    return jsonify(response), status_code


def request_data():

    data = request.get_json(silent=True)

    return data if isinstance(data, dict) else None


def amount_to_paise(value):

    try:
        amount = Decimal(str(value))

        if not amount.is_finite() or amount <= 0:
            return None

        if amount.as_tuple().exponent < -2:
            return None

        paise = amount * 100

        if paise != paise.to_integral_value():
            return None

        paise = int(paise)

        if paise > MAX_PAYMENT_PAISE:
            return None

        return paise

    except (InvalidOperation, TypeError, ValueError):
        return None


def paise_to_rupees(paise):

    return f"{Decimal(int(paise)) / Decimal('100'):.2f}"


def make_qr_data_url(payload):

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )

    qr.add_data(
        json.dumps(
            payload,
            separators=(",", ":"),
            sort_keys=True,
        )
    )

    qr.make(fit=True)

    image = qr.make_image(
        fill_color="black",
        back_color="white",
    )

    buffer = io.BytesIO()

    image.save(buffer, format="PNG")

    encoded = base64.b64encode(
        buffer.getvalue()
    ).decode("ascii")

    return f"data:image/png;base64,{encoded}"


def row_to_dict(row):

    if row is None:
        return None

    if isinstance(row, dict):
        return dict(row)

    try:
        return dict(row)

    except (TypeError, ValueError):
        return row


def _history_timestamp(value):
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return time.mktime(time.strptime(value, "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            return 0
    return 0


# ============================================================
# PAYMENT QR VALIDATION
# ============================================================

def validate_payment_qr_payload(payload):

    """
    Validate a merchant QR against the payment request
    stored in the local database.
    """

    if isinstance(payload, str):

        try:
            payload = json.loads(payload)

        except (json.JSONDecodeError, TypeError):
            return None, "Invalid QR JSON"

    if not isinstance(payload, dict):
        return None, "Invalid QR payload"

    if payload.get("protocol") != "netbridge-payment-v1":
        return None, "Unsupported payment QR protocol"

    if payload.get("mode") != "simulation_only":
        return None, "Only simulation payments are supported"

    if payload.get("currency") != "INR":
        return None, "Unsupported currency"

    request_id = payload.get("request_id")

    if not isinstance(request_id, str) or not request_id.strip():
        return None, "Payment request ID is missing"

    try:
        merchant_id = str(payload["merchant_id"])

        receiver_device_id = str(
            payload["receiver_device_id"]
        )

        qr_amount_paise = amount_to_paise(
            payload["amount"]
        )

    except (KeyError, TypeError, ValueError):
        return None, "Required payment details are missing"

    if qr_amount_paise is None:
        return None, "Invalid payment amount"

    payment_request = get_payment_request(request_id)

    if not payment_request:
        return None, "Payment request was not found"

    payment_request = row_to_dict(payment_request)

    if not isinstance(payment_request, dict):
        return None, "Invalid payment request record"

    stored_merchant_id = str(
        payment_request.get("merchant_id", "")
    )

    stored_device_id = str(
        payment_request.get("receiver_device_id", "")
    )

    stored_amount = payment_request.get("amount_paise")

    stored_status = payment_request.get("status")

    stored_expiry = payment_request.get("expires_at")

    stored_currency = payment_request.get("currency", "INR")

    if stored_merchant_id != merchant_id:
        return None, "Merchant ID does not match the stored request"

    if stored_device_id != receiver_device_id:
        return None, "Receiver device does not match the stored request"

    if stored_currency != "INR":
        return None, "Unsupported stored currency"

    if stored_amount is None or int(stored_amount) != qr_amount_paise:
        return None, "QR amount does not match the stored request"

    if stored_status != "pending":
        return None, "Payment request is no longer pending"

    if stored_expiry is None:
        return None, "Payment request expiry is missing"

    if float(stored_expiry) <= time.time():
        return None, "Payment request has expired"

    normalized = {
        "protocol": "netbridge-payment-v1",
        "request_id": request_id,
        "merchant_id": merchant_id,
        "receiver_device_id": receiver_device_id,
        "amount_paise": qr_amount_paise,
        "amount": paise_to_rupees(qr_amount_paise),
        "currency": "INR",
        "mode": "simulation_only",
        "expires_at": float(stored_expiry),
        "status": stored_status,
    }

    return normalized, None


# ============================================================
# WEB PAGES
# ============================================================

@app.route("/")
def home():

    return render_template("index.html")


@app.route("/customer")
def customer_page():

    return render_template("index.html")

@app.route("/service-worker.js", methods=["GET"])
def service_worker():
    response = send_from_directory(
        app.static_folder,
        "service-worker.js",
        mimetype="application/javascript",
    )
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response


@app.route("/merchant")
def merchant_page():

    return render_template("merchant.html")


@app.route("/far-wallet/customer2")
def far_customer_inbox_page():
    return render_template(
        "far_wallet.html",
        wallet_id="CUSTOMER002",
        upi_id="customer2@netbridge",
    )


# ============================================================
# HEALTH API
# ============================================================

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "success": True,
        "application": "NetBridge",
        "service": "NetBridge",
        "status": "running",
        "mode": "simulation_only",
        "real_payments_enabled": False,
        "timestamp": time.time(),
    })
# ============================================================
# GOOGLE AUTHENTICATOR / TOTP API
# ============================================================

@app.route("/api/authenticator/session", methods=["GET"])
def authenticator_session_route():
    """Identify this server run so the customer app can clear stale keys."""
    response = jsonify({"app_session": APP_SESSION_ID, "mode": "simulation_only"})
    response.headers["Cache-Control"] = "no-store"
    return response, 200

@app.route("/api/authenticator/status", methods=["POST"])
def authenticator_status_route():

    data = request_data()

    if data is None:
        return jsonify({
            "status": "error",
            "message": "A valid JSON request body is required.",
        }), 400

    user_id = data.get("user_id")
    pin = data.get("pin")

    if not isinstance(user_id, str) or not user_id.strip():
        return jsonify({
            "status": "error",
            "message": "Wallet ID is required.",
        }), 400

    if not isinstance(pin, str) or not pin:
        return jsonify({
            "status": "error",
            "message": "Wallet PIN is required.",
        }), 400

    user_id = user_id.strip()

    if not verify_wallet_pin(user_id, pin):
        return jsonify({
            "status": "error",
            "message": "Wallet authentication failed.",
        }), 401

    return jsonify({
        "status": "success",
        "wallet_id": user_id,
        "authenticator_enabled": is_totp_enabled(user_id),
        "mode": "simulation_only",
    }), 200


@app.route("/api/authenticator/enroll", methods=["POST"])
def authenticator_enroll_route():

    data = request_data()

    if data is None:
        return jsonify({
            "status": "error",
            "message": "A valid JSON request body is required.",
        }), 400

    user_id = data.get("user_id")
    pin = data.get("pin")

    if not isinstance(user_id, str) or not user_id.strip():
        return jsonify({
            "status": "error",
            "message": "Wallet ID is required.",
        }), 400

    user_id = user_id.strip()

    if not isinstance(pin, str) or not pin:
        return jsonify({
            "status": "error",
            "message": "Wallet PIN is required.",
        }), 400

    if not verify_wallet_pin(user_id, pin):
        return jsonify({
            "status": "error",
            "message": "Wallet authentication failed.",
        }), 401

    try:

        if is_totp_enabled(user_id):
            return jsonify({
                "status": "error",
                "message": "Authenticator is already enabled.",
            }), 409

        secret = begin_totp_enrollment(user_id)

        provisioning_uri = get_provisioning_uri(
            secret,
            account_name=user_id,
            issuer="NetBridge",
        )

        qr_code_base64 = generate_qr_code(
            provisioning_uri
        )

        if not qr_code_base64:
            raise ValueError(
                "QR code generation failed."
            )

        qr_data_url = (
            "data:image/png;base64,"
            + qr_code_base64
        )

        return jsonify({
            "status": "success",
            "message": (
                "Scan the QR code in Google Authenticator "
                "and confirm using the current 6-digit code."
            ),
            "qr_code": qr_data_url,
            "qr_matrix": generate_qr_matrix(provisioning_uri),
            # The customer PWA encrypts this during enrollment so it can
            # verify future OTPs locally while offline.
            "offline_secret": secret,
            "wallet_id": user_id,
            "digits": 6,
            "period_seconds": 30,
            "mode": "simulation_only",
            "real_payments_enabled": False,
        }), 200

    except ValueError as exc:

        return jsonify({
            "status": "error",
            "message": str(exc),
        }), 400

    except Exception:

        logger.exception(
            "Authenticator enrollment failed."
        )

        return jsonify({
            "status": "error",
            "message": (
                "Could not start authenticator enrollment."
            ),
        }), 500


@app.route("/api/authenticator/refresh", methods=["POST"])
def authenticator_refresh_route():
    """Replace a customer's Authenticator setup after wallet PIN proof."""
    data = request_data()
    if data is None:
        return jsonify({"status": "error", "message": "A valid JSON request body is required."}), 400
    user_id = data.get("user_id")
    pin = data.get("pin")
    if user_id != "CUSTOMER001" or not isinstance(pin, str) or not verify_wallet_pin(user_id, pin):
        return jsonify({"status": "error", "message": "Wallet authentication failed."}), 401
    from authenticator.totp_store import get_connection as get_totp_connection
    from contextlib import closing
    with closing(get_totp_connection()) as connection:
        connection.execute("DELETE FROM wallet_totp WHERE user_id = ?", (user_id,))
        connection.commit()
    return jsonify({"status": "success", "message": "Authenticator setup cleared. Generate a fresh QR now."}), 200


@app.route("/api/authenticator/offline-credential", methods=["POST"])
def authenticator_offline_credential_route():
    """Re-cache a customer's TOTP secret after online PIN and OTP proof."""
    data = request_data()
    if data is None:
        return jsonify({"status": "error", "message": "A valid JSON request body is required."}), 400

    user_id = data.get("user_id")
    pin = data.get("pin")
    otp = data.get("otp")
    if not isinstance(user_id, str) or not user_id.strip():
        return jsonify({"status": "error", "message": "Wallet ID is required."}), 400
    if not isinstance(pin, str) or not pin:
        return jsonify({"status": "error", "message": "Wallet PIN is required."}), 400
    if not isinstance(otp, str) or len(otp) != 6 or not otp.isascii() or not otp.isdigit():
        return jsonify({"status": "error", "message": "Enter a valid 6-digit authenticator code."}), 400

    user_id = user_id.strip()
    if not verify_wallet_pin(user_id, pin):
        return jsonify({"status": "error", "message": "Wallet authentication failed."}), 401
    if not verify_totp_for_reconnect(user_id, otp):
        return jsonify({"status": "error", "message": "Authenticator verification failed."}), 401

    secret = get_totp_secret(user_id)
    if not secret:
        return jsonify({"status": "error", "message": "Authenticator is not enabled."}), 409
    return jsonify({
        "status": "success",
        "offline_secret": secret,
        "mode": "simulation_only",
    }), 200


@app.route("/api/authenticator/confirm", methods=["POST"])
def authenticator_confirm_route():

    data = request_data()

    if data is None:
        return jsonify({
            "status": "error",
            "message": "A valid JSON request body is required.",
        }), 400

    user_id = data.get("user_id")
    pin = data.get("pin")
    otp = data.get("otp")

    if not isinstance(user_id, str) or not user_id.strip():
        return jsonify({
            "status": "error",
            "message": "Wallet ID is required.",
        }), 400

    user_id = user_id.strip()

    if not isinstance(pin, str) or not pin:
        return jsonify({
            "status": "error",
            "message": "Wallet PIN is required.",
        }), 400

    if not verify_wallet_pin(user_id, pin):
        return jsonify({
            "status": "error",
            "message": "Wallet authentication failed.",
        }), 401

    if not isinstance(otp, str) or (
        len(otp) != 6 or not otp.isdigit()
    ):
        return jsonify({
            "status": "error",
            "message": (
                "Enter a valid 6-digit authenticator code."
            ),
        }), 400

    try:

        if is_totp_enabled(user_id):
            return jsonify({
                "status": "error",
                "message": "Authenticator is already enabled.",
            }), 409

        activated = confirm_totp_enrollment(
            user_id,
            otp,
        )

        if not activated:
            return jsonify({
                "status": "error",
                "message": (
                    "Authenticator confirmation failed. "
                    "Check the code and try again."
                ),
            }), 400

        return jsonify({
            "status": "success",
            "message": (
                "Authenticator connected successfully."
            ),
            "authenticator_enabled": True,
            "wallet_id": user_id,
            "mode": "simulation_only",
        }), 200

    except Exception:

        logger.exception(
            "Authenticator confirmation failed."
        )

        return jsonify({
            "status": "error",
            "message": "Could not confirm authenticator.",
        }), 500


# ============================================================
# WALLET API
# ============================================================

@app.route("/api/wallets", methods=["GET"])
def wallets_route():
    """Return demo wallets using the database's canonical schema."""
    try:
        connection = get_connection()
        try:
            rows = connection.execute(
                "SELECT user_id, name, balance FROM wallets ORDER BY user_id"
            ).fetchall()
        finally:
            connection.close()

        wallets = []
        for row in rows:
            wallet = row_to_dict(row)
            balance_paise = int(wallet["balance"])
            wallets.append({
                "user_id": wallet["user_id"],
                "name": wallet["name"],
                "balance_paise": balance_paise,
                "balance_rupees": paise_to_rupees(balance_paise),
            })
        return jsonify(wallets), 200
    except Exception:
        logger.exception("Could not retrieve wallets.")
        return error_response("Could not retrieve wallets.", 500)


@app.route("/api/wallets/<wallet_id>", methods=["GET"])
def wallet_details_route(wallet_id):
    try:
        wallet = get_wallet(wallet_id)
        if not wallet:
            return error_response("Wallet not found.", 404)

        wallet_data = row_to_dict(wallet)
        balance_paise = int(wallet_data["balance"])
        return jsonify({
            "user_id": wallet_data["user_id"],
            "name": wallet_data["name"],
            "balance": balance_paise,
            "balance_paise": balance_paise,
            "balance_rupees": paise_to_rupees(balance_paise),
            "mode": "simulation_only",
        }), 200
    except Exception:
        logger.exception("Could not retrieve wallet details.")
        return error_response("Could not retrieve wallet details.", 500)


@app.route("/api/wallets/<wallet_id>/balance", methods=["GET"])
def wallet_balance_route(wallet_id):
    try:
        balance = get_wallet_balance(wallet_id)
        if balance is None:
            return error_response("Wallet not found.", 404)
        return jsonify({
            "success": True,
            "wallet_id": wallet_id,
            "balance_paise": int(balance),
            "balance_rupees": paise_to_rupees(balance),
            "currency": "INR",
            "mode": "simulation_only",
        }), 200
    except Exception:
        logger.exception("Could not retrieve wallet balance.")
        return error_response("Could not retrieve wallet balance.", 500)


@app.route("/api/wallets/<wallet_id>/transactions", methods=["GET"])
def wallet_transactions_route(wallet_id):
    if get_wallet(wallet_id) is None:
        return error_response("Wallet not found.", 404)
    try:
        history = get_transaction_history(wallet_id)
        for item in history:
            if item.get("status") == "far_payment_delivered_simulation":
                item["status"] = (
                    "payment_sent_far_simulation"
                    if str(item.get("sender_id")) == wallet_id
                    else "payment_received_far_simulation"
                )
        offline_records = []
        for ledger_status in (
            "pending_reconciliation", "reconciled", "conflict", "rejected"
        ):
            offline_records.extend(
                item for item in list_offline_payments(
                    status=ledger_status, limit=1000
                )
                if (
                    str(item.get("customer_user_id")) == wallet_id
                    or str(item.get("merchant_user_id")) == wallet_id
                )
            )
        for item in offline_records:
            customer_side = str(item.get("customer_user_id")) == wallet_id
            ledger_status = str(item.get("status", ""))
            display_status = (
                "payment_sent_simulation" if customer_side
                else "payment_received_simulation"
            ) if ledger_status in {"pending_reconciliation", "reconciled"} else ledger_status
            history.append({
                "transaction_id": item.get("authorization_id"),
                "amount_paise": int(item.get("amount_paise", 0)),
                "amount": paise_to_rupees(item.get("amount_paise", 0)),
                "status": display_status,
                "created_at": item.get("received_at"),
                "customer_user_id": item.get("customer_user_id"),
                "merchant_user_id": item.get("merchant_user_id"),
                "type": "offline_simulation",
            })
        for item in list_offline_qr_receipts(wallet_id):
            customer_side = str(item.get("customer_user_id")) == wallet_id
            receipt_status = str(item.get("payment_status", ""))
            display_status = (
                "payment_sent_simulation"
                if customer_side else "payment_received_simulation"
            ) if receipt_status == "accepted_for_simulation_review" else receipt_status
            history.append({
                "transaction_id": item.get("receipt_id"),
                "amount_paise": int(item.get("amount_paise", 0)),
                "amount": paise_to_rupees(item.get("amount_paise", 0)),
                "status": display_status,
                "created_at": item.get("received_at"),
                "customer_user_id": item.get("customer_user_id"),
                "merchant_user_id": item.get("merchant_user_id"),
                "type": "offline_qr_simulation",
            })
        history.sort(
            key=lambda item: _history_timestamp(item.get("created_at")),
            reverse=True,
        )
        history = history[:100]
        return jsonify({
            "success": True,
            "wallet_id": wallet_id,
            "transactions": history,
            "count": len(history),
            "mode": "simulation_only",
        }), 200
    except Exception:
        logger.exception("Could not retrieve wallet transaction history.")
        return error_response("Could not retrieve transaction history.", 500)


@app.route("/api/far-payments", methods=["POST"])
def far_payment_route():
    """Settle a fictional remote NetBridge payment; never moves real funds."""
    data = request_data()
    if data is None:
        return error_response("A valid JSON request body is required.")
    sender_id = data.get("sender_id")
    recipient_id = str(data.get("recipient_upi_id", "")).strip().casefold()
    pin = data.get("pin")
    amount_paise = data.get("amount_paise")
    transaction_id = data.get("transaction_id")
    recipient_accounts = {
        "merchant@netbridge": "MERCHANT001",
        "merchant001@netbridge": "MERCHANT001",
        "customer2@netbridge": "CUSTOMER002",
    }
    if sender_id != "CUSTOMER001" or recipient_id not in recipient_accounts:
        return error_response("NetBridge recipient ID was not found.", 404)
    if not isinstance(pin, str) or not verify_wallet_pin(sender_id, pin):
        return error_response("Incorrect customer demo PIN.", 401)
    if type(amount_paise) is not int or amount_paise <= 0 or amount_paise > MAX_PAYMENT_PAISE:
        return error_response("Enter an amount from ₹0.01 to ₹5,000.00.")
    if not isinstance(transaction_id, str) or not (16 <= len(transaction_id) <= 80):
        return error_response("A valid payment reference is required.")
    try:
        outcome = process_demo_far_payment(
            sender_id, recipient_accounts[recipient_id], amount_paise, transaction_id
        )
        if outcome.get("status") != "success":
            return error_response(outcome.get("message", "Payment could not be completed."), 400)
        return jsonify({
            "success": True,
            "status": "delivered",
            "duplicate": bool(outcome.get("duplicate", False)),
            "transaction_id": transaction_id,
            "sender_balance_paise": outcome["sender_balance_paise"],
            "receiver_balance_paise": outcome["receiver_balance_paise"],
            "recipient_upi_id": recipient_id,
            "mode": "simulation_only",
            "real_payments_enabled": False,
            "message": "Payment delivered to the NetBridge demo merchant wallet.",
        }), 200
    except Exception:
        logger.exception("Far payment simulation failed.")
        return error_response("Could not complete the simulated far payment.", 500)


# Device identity and challenge APIs used by trusted-device enrollment.
@app.route("/api/auth/identity", methods=["GET"])
def auth_identity_route():
    try:
        identity = get_or_create_identity()
        return jsonify({
            "status": "success",
            "device_id": identity["device_id"],
            "public_key": identity["public_key"],
        }), 200
    except Exception:
        logger.exception("Could not load local device identity.")
        return error_response("Could not load device identity.", 500)


@app.route("/api/auth/challenge", methods=["POST"])
def auth_challenge_route():
    data = request_data()
    if data is None:
        return error_response("A valid JSON request body is required.", 400)

    device_id = data.get("device_id")
    if not isinstance(device_id, str) or not device_id.strip():
        return error_response("device_id is required.", 400)

    if not is_device_trusted(device_id):
        return error_response("This device is not trusted.", 403)

    try:
        challenge = challenge_manager.issue_challenge(device_id)
        return jsonify({"status": "success", **challenge}), 200
    except ValueError as exc:
        return error_response(str(exc), 400)
    except Exception:
        logger.exception("Could not issue authentication challenge.")
        return error_response("Could not issue authentication challenge.", 500)


@app.route("/api/devices/register-local", methods=["POST"])
def register_local_device_route():
    data = request_data()
    if data is None:
        return error_response("A valid JSON request body is required.", 400)

    owner_user_id = str(
        data.get("owner_user_id") or data.get("user_id") or ""
    ).strip()
    pin = data.get("pin")
    device_name = data.get("device_name", "This device")

    if not owner_user_id:
        return error_response("owner_user_id is required.", 400)
    if not validate_pin(pin):
        return error_response("A valid 4-digit wallet PIN is required.", 400)
    if data.get("approved") is not True:
        return error_response("Explicit device approval is required.", 403)
    if not verify_wallet_pin(owner_user_id, pin):
        return error_response("Incorrect wallet PIN.", 401)

    try:
        identity = get_or_create_identity()
        result = register_trusted_device(
            device_id=identity["device_id"],
            owner_user_id=owner_user_id,
            public_key=identity["public_key"],
            device_name=str(device_name)[:80],
            approved=True,
        )
        if result.get("status") != "success":
            return error_response(result.get("message", "Registration failed."), 400)
        return jsonify({
            "success": True,
            "status": "success",
            "device_id": identity["device_id"],
            "message": result.get("message", "Trusted device registered."),
            "mode": "simulation_only",
        }), 200
    except Exception:
        logger.exception("Local device registration failed.")
        return error_response("Could not register this device.", 500)


@app.route("/api/devices/trusted", methods=["GET"])
def trusted_devices_route():
    try:
        devices = list_trusted_devices()
        safe_devices = []
        for item in devices:
            device = row_to_dict(item)
            if not isinstance(device, dict):
                continue
            safe_devices.append({
                key: value for key, value in device.items()
                if key not in {"private_key", "private_seed", "secret", "seed"}
            })
        return jsonify({
            "status": "success",
            "count": len(safe_devices),
            "devices": safe_devices,
        }), 200
    except Exception:
        logger.exception("Could not list trusted devices.")
        return error_response("Could not retrieve trusted devices.", 500)


# ============================================================
# MERCHANT QR API
# ============================================================

@app.route("/api/merchant/qr", methods=["POST"])
def merchant_qr_route():

    data = request_data()

    if data is None:
        return error_response(
            "A valid JSON request body is required."
        )

    merchant_id = data.get("merchant_id")
    device_id = data.get("device_id")
    amount = data.get("amount")
    pin = data.get("pin")

    if not all([merchant_id, device_id, amount, pin]):
        return error_response(
            "Merchant ID, device ID, amount and PIN are required."
        )

    if not isinstance(merchant_id, str):
        return error_response("Invalid merchant ID.")

    if not isinstance(device_id, str):
        return error_response("Invalid device ID.")

    if not isinstance(pin, str):
        return error_response("Invalid PIN.")

    if not verify_wallet_pin(merchant_id, pin):
        return error_response(
            "Merchant authentication failed.",
            401,
        )

    amount_paise = amount_to_paise(amount)

    if amount_paise is None:
        return error_response(
            "Invalid amount. Maximum transaction amount is ₹5,000."
        )

    try:

        payment_request = create_payment_request(
            merchant_id=merchant_id,
            receiver_device_id=device_id,
            amount_paise=amount_paise,
        )

        if not payment_request:
            return error_response(
                "Could not create payment request.",
                500,
            )

        request_data_result = row_to_dict(
            payment_request
        )

        qr_payload = {
            "protocol": "netbridge-payment-v1",
            "request_id": request_data_result["request_id"],
            "merchant_id": merchant_id,
            "receiver_device_id": device_id,
            "amount": paise_to_rupees(amount_paise),
            "currency": "INR",
            "mode": "simulation_only",
        }

        qr_code = make_qr_data_url(qr_payload)

        return jsonify({
            "success": True,
            "status": "created",
            "payment_request": request_data_result,
            "qr_payload": qr_payload,
            "qr_code": qr_code,
            "mode": "simulation_only",
            "real_payments_enabled": False,
        }), 200

    except Exception:

        logger.exception(
            "Merchant QR creation failed."
        )

        return error_response(
            "Could not create merchant payment QR.",
            500,
        )


@app.route(
    "/api/merchant/qr/validate",
    methods=["POST"],
)
def validate_qr_route():

    data = request_data()

    if data is None:
        return error_response(
            "A valid JSON request body is required."
        )

    qr_payload = data.get("qr_payload")

    if qr_payload is None:
        return error_response(
            "QR payload is required."
        )

    try:

        normalized, error = validate_payment_qr_payload(
            qr_payload
        )

        if error:
            return error_response(error, 400)

        return jsonify({
            "success": True,
            "status": "valid",
            "payment": normalized,
            "mode": "simulation_only",
        }), 200

    except Exception:

        logger.exception("QR validation failed.")

        return error_response(
            "Could not validate payment QR.",
            500,
        )


# ============================================================
# MERCHANT PAYMENT REQUESTS
# ============================================================

@app.route(
    "/api/merchant/payment-requests",
    methods=["GET"],
)
def merchant_payment_requests_route():

    merchant_id = request.args.get("merchant_id")

    if not merchant_id:
        return error_response(
            "Merchant ID is required."
        )

    try:

        records = list_payment_requests(merchant_id)

        return jsonify({
            "success": True,
            "merchant_id": merchant_id,
            "payment_requests": [
                row_to_dict(record)
                for record in records
            ],
            "mode": "simulation_only",
        }), 200

    except Exception:

        logger.exception(
            "Could not retrieve merchant payment requests."
        )

        return error_response(
            "Could not retrieve payment requests.",
            500,
        )


@app.route(
    "/api/merchant/payment-requests/<request_id>",
    methods=["GET"],
)
def merchant_payment_request_status_route(request_id):

    try:

        payment_request = get_payment_request(
            request_id
        )

        if not payment_request:
            return error_response(
                "Payment request not found.",
                404,
            )

        return jsonify({
            "success": True,
            "payment_request": row_to_dict(
                payment_request
            ),
            "mode": "simulation_only",
        }), 200

    except Exception:

        logger.exception(
            "Could not retrieve payment request status."
        )

        return error_response(
            "Could not retrieve payment request.",
            500,
        )


# ============================================================
# TRUSTED DEVICE REVOCATION
# ============================================================

@app.route(
    "/api/devices/<device_id>/revoke",
    methods=["POST"],
)
def revoke_device(device_id):

    trusted_device = get_trusted_device(device_id)

    if not trusted_device:
        return error_response(
            "Trusted device not found.",
            404,
        )

    data = request_data()

    if data is None:
        return error_response(
            "JSON request body is required."
        )

    user_id = data.get("user_id")
    pin = data.get("pin")

    if not user_id or not pin:
        return error_response(
            "user_id and pin are required."
        )

    if not verify_wallet_pin(user_id, pin):
        return error_response(
            "Incorrect wallet PIN.",
            401,
        )

    trusted_device = row_to_dict(trusted_device)

    owner_id = (
        trusted_device.get("wallet_id")
        or trusted_device.get("owner_user_id")
    )

    if str(owner_id) != str(user_id):
        return error_response(
            "You cannot revoke another wallet's device.",
            403,
        )

    try:

        result = revoke_trusted_device(device_id)

        return jsonify({
            "success": True,
            "status": "success",
            "device_id": device_id,
            "result": result,
        }), 200

    except Exception:

        logger.exception(
            "Device revocation failed."
        )

        return error_response(
            "Device revocation failed.",
            500,
        )


# ============================================================
# TRANSACTION CREATION
# ============================================================

@app.route(
    "/api/transactions/create",
    methods=["POST"],
)
def create_payment_transaction():

    data = request_data()

    if data is None:
        return error_response(
            "JSON request body is required."
        )

    sender_id = data.get("sender_id")
    pin = data.get("pin")
    receiver_device_id = data.get("receiver_device_id")
    amount_input = data.get("amount")
    qr_data = data.get("qr_data")

    if not sender_id or not pin:
        return error_response(
            "sender_id and pin are required."
        )

    if not isinstance(pin, str) or not validate_pin(pin):
        return error_response(
            "Invalid PIN format."
        )

    if not verify_wallet_pin(sender_id, pin):
        return error_response(
            "Incorrect wallet PIN.",
            401,
        )

    amount_paise = amount_to_paise(amount_input)

    if amount_paise is None:
        return error_response(
            "Invalid amount. Maximum transaction amount is ₹5,000.00"
        )

    payment_request_id = None

    if qr_data is not None:

        payment_request, error = validate_payment_qr_payload(
            qr_data
        )

        if error:
            return error_response(error, 400)

        if amount_paise != payment_request["amount_paise"]:
            return error_response(
                "Entered amount does not match the merchant QR amount."
            )

        if str(receiver_device_id) != str(
            payment_request["receiver_device_id"]
        ):
            return error_response(
                "Receiver device does not match the merchant QR."
            )

        receiver_device_id = (
            payment_request["receiver_device_id"]
        )

        payment_request_id = (
            payment_request["request_id"]
        )

    if not receiver_device_id:
        return error_response(
            "receiver_device_id is required."
        )

    receiver_device = get_trusted_device(
        str(receiver_device_id)
    )

    if not receiver_device:
        return error_response(
            "Receiver device is not trusted.",
            403,
        )

    receiver_device = row_to_dict(receiver_device)

    if not isinstance(receiver_device, dict):
        return error_response(
            "Invalid receiver device record.",
            500,
        )

    receiver_wallet_id = receiver_device.get("wallet_id")

    if payment_request_id:

        if str(receiver_wallet_id) != str(
            payment_request["merchant_id"]
        ):
            return error_response(
                "Receiver device does not belong to the merchant.",
                403,
            )

    try:

        identity = get_or_create_identity()

        if str(identity.get("device_id")) == str(
            receiver_device_id
        ):
            return error_response(
                "Sender and receiver devices cannot be the same."
            )

        sender_device = get_trusted_device(
            str(identity.get("device_id"))
        )

        if not sender_device:
            return error_response(
                "Register this device to the sender wallet before paying.",
                403,
            )

        sender_device = row_to_dict(sender_device)

        if not isinstance(sender_device, dict):
            return error_response(
                "Invalid sender device record.",
                500,
            )

        if str(sender_device.get("wallet_id")) != str(sender_id):
            return error_response(
                "Local device is not registered to the sender wallet.",
                403,
            )

        transaction = create_transaction(
            sender_identity=identity,
            receiver_device_id=str(receiver_device_id),
            amount=paise_to_rupees(amount_paise),
            payment_request_id=payment_request_id,
        )

        return jsonify({
            "success": True,
            "transaction": transaction,
            "message": (
                "Transaction created; processing is still required."
            ),
            "real_payments_enabled": False,
            "mode": "simulation_only",
        }), 200

    except ValueError as exc:

        return error_response(str(exc), 400)

    except Exception:

        logger.exception(
            "Transaction creation failed."
        )

        return error_response(
            "Transaction creation failed.",
            500,
        )
# ============================================================
# TRANSACTION PROCESSING
# ============================================================

@app.route(
    "/api/transactions/process",
    methods=["POST"],
)
def process_transaction_route():

    data = request_data()

    if data is None:
        return error_response(
            "A valid JSON request body is required."
        )

    signed_transaction = data.get("signed_transaction")
    totp_otp = data.get("totp_otp")

    if not isinstance(signed_transaction, dict):
        return error_response(
            "Signed transaction is required."
        )

    if not isinstance(totp_otp, str) or (
        len(totp_otp) != 6 or not totp_otp.isdigit()
    ):
        return error_response(
            "Enter a valid 6-digit authenticator code."
        )

    try:

        result = process_transaction(
            signed_transaction,
            totp_otp=totp_otp,
        )

        if result.get("status") == "success":
            return jsonify(result), 200

        return jsonify(result), 400

    except Exception:

        logger.exception(
            "Unexpected error while processing a transaction."
        )

        return error_response(
            "An unexpected payment-processing error occurred.",
            500,
        )


# ============================================================
# OFFLINE QR PAYMENT HELPERS
# ============================================================

def _trusted_device_for_user(device_id, user_id):

    """Return a trusted device only when it belongs to the user."""

    device = get_trusted_device(str(device_id))

    device = row_to_dict(device)

    if not isinstance(device, dict):
        return None

    if device.get("status") != "trusted":
        return None

    owner_id = (
        device.get("wallet_id")
        or device.get("owner_user_id")
    )

    if str(owner_id) != str(user_id):
        return None

    return device


def _parse_offline_qr(value, expected_type):

    """Parse an offline QR string or decoded payload dictionary."""

    if isinstance(value, dict):
        value = json.dumps(
            value,
            separators=(",", ":"),
        )

    payload = parse_qr_payload(value)

    if payload.get("type") != expected_type:
        raise ValueError(
            f"Expected a {expected_type.replace('_', ' ')} QR."
        )

    return payload["data"]


# ============================================================
# OFFLINE MERCHANT PAYMENT REQUEST
# ============================================================

@app.route(
    "/api/offline/merchant/request",
    methods=["POST"],
)
def offline_merchant_request():
    """Create one merchant QR backed by a server-stored request.

    This is a simulation-only flow. It does not require trusted-device
    registration and does not use a second customer authorization QR.
    """
    data = request_data()
    if data is None:
        return error_response("JSON request body is required.")

    merchant_id = str(data.get("merchant_id", "")).strip()
    pin = data.get("pin")
    amount = data.get("amount")

    if not merchant_id or not isinstance(pin, str) or amount is None:
        return error_response("merchant_id, pin and amount are required.")

    if not verify_wallet_pin(merchant_id, pin):
        return error_response("Incorrect merchant wallet PIN.", 401)

    amount_paise = amount_to_paise(amount)
    if amount_paise is None:
        return error_response("Invalid amount. Maximum transaction amount is ₹5,000.")

    try:
        identity = get_or_create_identity()
        stored_request = create_payment_request(
            merchant_id=merchant_id,
            receiver_device_id=str(identity["device_id"]),
            amount_paise=amount_paise,
            require_trusted_device=False,
        )

        if not isinstance(stored_request, dict) or stored_request.get("status") != "success":
            return error_response(
                stored_request.get("message", "Could not create payment request."),
                400,
            )

        request_details = {
            "protocol": "netbridge-offline-v1",
            "mode": "simulation_only",
            "request_id": stored_request["request_id"],
            "merchant_user_id": merchant_id,
            "merchant_device_id": str(identity["device_id"]),
            "amount_paise": amount_paise,
            "currency": "INR",
            "created_at": int(stored_request["created_at"]),
            "expires_at": int(stored_request["expires_at"]),
            "nonce": str(stored_request["request_id"]),
        }

        qr_text = create_qr_payload(
            "payment_request",
            {"request": request_details},
        )
        qr_payload = parse_qr_payload(qr_text)

        return jsonify({
            "success": True,
            "mode": "simulation_only",
            "qr_data": qr_text,
            "qr_image": make_qr_data_url(qr_payload),
            "request": request_details,
            "message": "Merchant request QR created. The customer scans it and shares a 10-character confirmation code for manual checking on this merchant device.",
            "real_payments_enabled": False,
        }), 200

    except ValueError as exc:
        return error_response(str(exc), 400)
    except Exception:
        logger.exception("Offline merchant request creation failed.")
        return error_response("Could not create offline payment request.", 500)


# ============================================================
# OFFLINE CUSTOMER AUTHORIZATION
# ============================================================

@app.route("/api/offline/customer/authorize", methods=["POST"])
def offline_customer_authorize():
    """Retire the legacy one-scan route; the current offline UI uses a typed confirmation code."""
    return error_response(
        "This legacy route is disabled. Use the merchant request QR and the customer's manual confirmation code for this simulation.",
        410,
    )


# ============================================================
# OFFLINE MERCHANT ACCEPTANCE
# ============================================================

@app.route(
    "/api/offline/merchant/accept",
    methods=["POST"],
)
def offline_merchant_accept():
    """Retained legacy API for older QR-only clients; the current merchant page accepts typed confirmation codes.

    This endpoint validates the receipt against the merchant request stored
    on this PC and atomically consumes that request. It deliberately does
    not claim cryptographic customer identity verification or real settlement.
    """
    data = request_data()
    if data is None:
        return error_response("JSON request body is required.")

    merchant_id = str(data.get("merchant_id", "")).strip()
    pin = data.get("pin")
    merchant_qr = data.get("merchant_qr")
    customer_qr = data.get("customer_qr")

    if not all((merchant_id, pin, merchant_qr, customer_qr)):
        return error_response(
            "merchant_id, pin, merchant_qr and customer_qr are required."
        )
    if not isinstance(pin, str) or not verify_wallet_pin(merchant_id, pin):
        return error_response("Incorrect merchant wallet PIN.", 401)

    try:
        merchant_data = _parse_offline_qr(merchant_qr, "payment_request")
        receipt_data = _parse_offline_qr(customer_qr, "payment_receipt")
        request_details = merchant_data.get("request")
        receipt = receipt_data.get("receipt")
        if not isinstance(request_details, dict) or not isinstance(receipt, dict):
            raise ValueError("QR payload is incomplete.")

        if str(request_details.get("merchant_user_id")) != merchant_id:
            return error_response("Merchant QR belongs to another merchant.", 403)

        request_id = request_details.get("request_id")
        stored = get_payment_request(request_id)
        if not stored:
            return error_response("Payment request was not found on this merchant PC.", 404)
        if stored.get("status") != "pending":
            return error_response("Payment request has already been used or is no longer pending.", 409)
        if str(stored.get("merchant_id")) != merchant_id:
            return error_response("Stored payment request belongs to another merchant.", 403)

        # Cross-check QR details against the server-side pending request.
        checks = {
            "request_id": stored.get("request_id"),
            "merchant_user_id": merchant_id,
            "merchant_device_id": stored.get("receiver_device_id"),
            "amount_paise": stored.get("amount_paise"),
            "currency": "INR",
            "created_at": stored.get("created_at"),
            "expires_at": stored.get("expires_at"),
        }
        for field, expected in checks.items():
            if request_details.get(field) != expected:
                raise ValueError(f"Merchant QR does not match stored request ({field}).")

        result = validate_payment_receipt(receipt, request_details)
        recorded = record_offline_qr_receipt(receipt, request_id)
        if recorded.get("status") != "success":
            return error_response(
                recorded.get("message", "Could not consume payment request."),
                409,
            )

        return jsonify({
            "success": True,
            "mode": "simulation_only",
            "payment_status": "accepted_for_simulation",
            "result": result,
            "message": (
                "Payment received and recorded in NetBridge transaction history "
                "as a simulation. No real money was transferred."
            ),
            "real_payments_enabled": False,
        }), 200

    except ValueError as exc:
        return error_response(str(exc), 400)
    except Exception:
        logger.exception("Offline merchant receipt acceptance failed.")
        return error_response("Could not validate or record customer receipt.", 500)


# ============================================================
# OFFLINE LEDGER
# ============================================================

@app.route(
    "/api/offline/ledger",
    methods=["GET"],
)
def offline_ledger_records():

    user_id = request.args.get(
        "user_id",
        "",
    ).strip()

    pin = request.args.get(
        "pin",
        "",
    )

    status = request.args.get(
        "status",
        "pending_reconciliation",
    )

    if not user_id or not pin:
        return error_response(
            "user_id and pin are required.",
            400,
        )

    if not verify_wallet_pin(user_id, pin):
        return error_response(
            "Incorrect wallet PIN.",
            401,
        )

    try:

        records = list_offline_payments(
            status=status,
            limit=1000,
        )

        records = [
            item for item in records
            if (
                str(item.get("customer_user_id")) == user_id
                or str(item.get("merchant_user_id")) == user_id
            )
        ][:100]

        return jsonify({
            "success": True,
            "mode": "simulation_only",
            "payments": records,
            "real_payments_enabled": False,
        }), 200

    except ValueError as exc:

        return error_response(str(exc), 400)

    except Exception:

        logger.exception(
            "Offline ledger retrieval failed."
        )

        return error_response(
            "Could not retrieve offline ledger.",
            500,
        )


# ============================================================
# CUSTOMER OFFLINE SPENDING
# ============================================================

@app.route(
    "/api/offline/spending/<customer_id>",
    methods=["GET"],
)
def offline_customer_spending(customer_id):

    pin = request.args.get(
        "pin",
        "",
    )

    if not pin:
        return error_response(
            "Wallet PIN is required.",
            400,
        )

    if not verify_wallet_pin(customer_id, pin):
        return error_response(
            "Incorrect wallet PIN.",
            401,
        )

    try:

        spending = get_customer_offline_spending(
            customer_id
        )

        return jsonify({
            "success": True,
            "mode": "simulation_only",
            "spending": spending,
            "real_payments_enabled": False,
        }), 200

    except ValueError as exc:

        return error_response(str(exc), 400)

    except Exception:

        logger.exception(
            "Offline spending lookup failed."
        )

        return error_response(
            "Could not retrieve offline spending.",
            500,
        )


# ============================================================
# LEGACY PAYMENT ROUTE DISABLED
# ============================================================

@app.route(
    "/api/pay",
    methods=["POST"],
)
def legacy_pay():

    return error_response(
        "Legacy payment route is disabled.",
        410,
        code="LEGACY_PAYMENT_DISABLED",
    )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    project_dir = Path(__file__).resolve().parent
    tls_cert = Path(os.environ.get(
        "NETBRIDGE_TLS_CERT", str(project_dir / "netbridge-lan-cert.pem")
    )).expanduser().resolve()
    tls_key = Path(os.environ.get(
        "NETBRIDGE_TLS_KEY", str(project_dir / "netbridge-lan-key.pem")
    )).expanduser().resolve()
    ssl_context = (str(tls_cert), str(tls_key)) if tls_cert.is_file() and tls_key.is_file() else None
    reset_totp_enrollments()
    reset_demo_wallets_and_history()
    logger.info("Demo wallets restored and transaction history cleared for this app run.")
    logger.info("Authenticator enrollments cleared for this app run; customers must reconnect.")
    # Bind on all interfaces by default so Android devices on the same LAN
    # can reach the HTTPS server. Windows Firewall may still need a private
    # network inbound rule for TCP port 5001.
    host = os.environ.get("NETBRIDGE_HOST", "0.0.0.0")
    if host not in {"127.0.0.1", "localhost"} and ssl_context is None:
        raise RuntimeError(
            "Non-local hosting requires a trusted HTTPS certificate. "
            "Set NETBRIDGE_TLS_CERT and NETBRIDGE_TLS_KEY to the certificate and key files."
        )
    app.run(
        host=host,
        port=int(os.environ.get("NETBRIDGE_PORT", "5001")),
        debug=False,
        threaded=True,
        ssl_context=ssl_context,
    )
