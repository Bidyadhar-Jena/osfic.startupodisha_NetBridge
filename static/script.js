"use strict";

/* NetBridge customer app; demo wallet and QR receipt support local offline use. */

const CUSTOMER_ID = "CUSTOMER001";
const MAX_QR_IMAGE_BYTES = 5 * 1024 * 1024;
const AUTHENTICATOR_CONNECTED_KEY = "netbridge.authenticator.connected.v2";
const AUTHENTICATOR_SESSION_KEY = "netbridge.authenticator.server-session.customer.v1";
const OFFLINE_CREDENTIAL_KEY = `netbridge.offline.totp.${CUSTOMER_ID}.v1`;
const AUTHENTICATOR_REFRESH_KEY = "netbridge.authenticator.refresh-on-connect.v1";

let decodedMerchantQrText = null;
let decodedMerchantQrPayload = null;
let cameraStream = null;
let cameraFrameHandle = null;
let pageAuthenticatorConnected = false;
let pendingAuthenticatorPin = null;
let pendingAuthenticatorSecret = null;
let pendingAuthenticatorLocalOnly = false;
let paymentCompleted = false;
let customerHistoryPollTimer = null;
let pendingFarSyncPin = null;
let farPaymentSyncInProgress = false;

async function fetchWithTimeout(url, options = {}, timeoutMs = 2500) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, { ...options, signal: controller.signal });
    } finally {
        window.clearTimeout(timer);
    }
}

function hideInitialLoader() {
    const overlay = byId("appLoadingOverlay");
    if (!overlay) return;
    overlay.classList.add("is-hidden");
    window.setTimeout(() => overlay.remove(), 300);
}

function setButtonLoading(button, label = "Refreshing") {
    if (!button || button.dataset.loading === "true") return () => {};
    const previous = button.innerHTML;
    button.dataset.loading = "true";
    button.classList.add("is-loading");
    button.disabled = true;
    button.innerHTML = `<span class="loader-spinner button-loader" aria-hidden="true"></span>${label}…`;
    return () => {
        button.innerHTML = previous;
        button.disabled = false;
        button.classList.remove("is-loading");
        delete button.dataset.loading;
    };
}

async function refreshCustomerView({ button = null, pullIndicator = false } = {}) {
    const restoreButton = setButtonLoading(button);
    const indicator = byId("pullRefreshIndicator");
    if (pullIndicator && indicator) {
        indicator.classList.add("is-visible", "is-refreshing");
        const label = indicator.querySelector("span:last-child");
        if (label) label.textContent = "Refreshing…";
    }
    try {
        const restarted = await syncAuthenticatorServerSession();
        if (restarted) {
            pageAuthenticatorConnected = false;
            pendingAuthenticatorPin = null;
            pendingAuthenticatorLocalOnly = false;
            setAuthenticatorView("connect");
            openAuthenticatorModal();
            showMessage("authenticatorMessage", "NetBridge restarted. Enter your PIN to generate a fresh Authenticator QR.", "info");
        }
        if (pullIndicator) {
            // Pull-to-refresh rotates Authenticator setup after the customer
            // proves the wallet PIN. Wallet/history state is not reset here.
            localStorage.setItem(AUTHENTICATOR_REFRESH_KEY, "true");
            pageAuthenticatorConnected = false;
            pendingAuthenticatorPin = null;
            pendingAuthenticatorLocalOnly = false;
            setAuthenticatorView("connect");
            openAuthenticatorModal();
            showMessage("authenticatorMessage", "Enter your wallet PIN to generate a fresh Authenticator QR. Your wallet and history are unchanged.", "info");
        }
        await Promise.allSettled([loadCustomerWallet(), loadCustomerHistory()]);
    } finally {
        restoreButton();
        if (pullIndicator && indicator) {
            indicator.classList.remove("is-refreshing");
            const label = indicator.querySelector("span:last-child");
            if (label) label.textContent = "Pull to refresh";
            window.setTimeout(() => indicator.classList.remove("is-visible"), 450);
        }
    }
}

function isNetworkFailure(error) {
    return error instanceof TypeError || error?.name === "AbortError" || !navigator.onLine;
}

async function syncAuthenticatorServerSession() {
    try {
        const response = await fetchWithTimeout(
            "/api/authenticator/session",
            { method: "GET", cache: "no-store" },
            2500
        );
        if (!response.ok) return false;
        const data = await response.json();
        if (typeof data.app_session !== "string" || !data.app_session) return false;

        const previousSession = localStorage.getItem(AUTHENTICATOR_SESSION_KEY);
        const hadCredential = Boolean(localStorage.getItem(OFFLINE_CREDENTIAL_KEY));
        const serverRestarted = Boolean(previousSession && previousSession !== data.app_session);
        const sessionWasUntracked = !previousSession && hadCredential;
        const serverSessionChanged = previousSession !== data.app_session;

        // app.py starts a fresh demo session each run. Reset device-local demo
        // wallets/history and discard the stale Authenticator secret on change.
        if (serverSessionChanged) {
            NetBridgeOfflineStore.resetDemoState("CUSTOMER001");
            NetBridgeOfflineStore.resetDemoState("CUSTOMER002");
            NetBridgeOfflineStore.resetDemoState("MERCHANT001");
        }
        if (serverRestarted || sessionWasUntracked) {
            localStorage.removeItem(OFFLINE_CREDENTIAL_KEY);
            localStorage.removeItem(AUTHENTICATOR_CONNECTED_KEY);
        }
        localStorage.setItem(AUTHENTICATOR_SESSION_KEY, data.app_session);
        return serverRestarted || sessionWasUntracked;
    } catch (_) {
        // Keep the local Authenticator setup available when this is an offline visit.
        return false;
    }
}

function byId(id) {
    return document.getElementById(id);
}

function setText(id, value) {
    const element = byId(id);
    if (element) element.textContent = value;
}

function showMessage(id, message, type = "") {
    const element = byId(id);
    if (!element) return;

    element.textContent = message;
    element.dataset.state = type || (/\b(error|could not|failed|invalid|incorrect|unavailable|unable|cannot|denied|expired|required|not found|must|wrong|enter|choose)\b/i.test(message) ? "error" : "");
}

function formatINR(value) {
    const amount = Number(value);

    if (!Number.isFinite(amount)) {
        return "Invalid amount";
    }

    return new Intl.NumberFormat("en-IN", {
        style: "currency",
        currency: "INR",
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(amount);
}

function formatTransactionStatus(item) {
    const status = String(item?.status || "recorded");
    if (status === "payment_queued_offline") return "Pending · recipient has not received it";
    if (status === "payment_sent_far_simulation") return "Payment delivered (simulation)";
    if (status === "payment_received_far_simulation") return "Payment received (simulation)";
    if (status === "payment_sent_simulation") return "Payment sent (simulation)";
    if (status === "payment_received_simulation") return "Payment received (simulation)";
    if (
        status === "pending_reconciliation" ||
        status === "accepted_for_simulation_review"
    ) {
        return "Payment sent (simulation)";
    }
    return status.replaceAll("_", " ");
}

async function apiPost(url, body) {
    const response = await fetchWithTimeout(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        cache: "no-store",
        body: JSON.stringify(body)
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(
            data.message ||
            data.error ||
            `Request failed (${response.status}).`
        );
    }

    return data;
}

/* ==========================================
   CUSTOMER WALLET
========================================== */

async function loadCustomerWallet() {
    const balance = byId("customerBalance");
    const message = byId("walletMessage");

    if (!balance) return;

    balance.textContent = formatINR(NetBridgeOfflineStore.getBalance(CUSTOMER_ID) / 100);
    balance.classList.remove("skeleton-text");
    if (message) {
        message.textContent = "Local demo balance on this phone.";
        message.dataset.state = "info";
    }

    if (!navigator.onLine) return;

    try {
        const response = await fetchWithTimeout(
            `/api/wallets/${encodeURIComponent(CUSTOMER_ID)}/balance`,
            {
                method: "GET",
                cache: "no-store"
            },
            2500
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to load wallet.");
        }

        if (data.balance_rupees === undefined) {
            throw new Error("Wallet balance is missing.");
        }

        const amount = Number(data.balance_rupees);

        if (!Number.isFinite(amount)) {
            throw new Error("Invalid wallet balance.");
        }

        NetBridgeOfflineStore.seedFromServer(
            CUSTOMER_ID,
            Math.round(amount * 100)
        );
        balance.textContent = formatINR(NetBridgeOfflineStore.getBalance(CUSTOMER_ID) / 100);
        if (message) {
            const pending = NetBridgeOfflineStore.getPendingDelta(CUSTOMER_ID);
            message.textContent = pending
                ? "Showing this phone's saved demo balance, including offline payments."
                : "";
            message.dataset.state = pending ? "info" : "";
        }

    } catch (error) {
        console.error("Customer wallet:", error);
        try {
            balance.textContent = formatINR(NetBridgeOfflineStore.getBalance(CUSTOMER_ID) / 100);
        } catch (_) {
            balance.textContent = "Balance unavailable";
        }
        if (message) {
            message.textContent = "Offline demo balance saved on this phone. It does not sync to the merchant or another phone.";
            message.dataset.state = "info";
        }
    }
}

/* ==========================================
   CUSTOMER TRANSACTION HISTORY
========================================== */

async function loadCustomerHistory() {
    const container = byId("transactionHistory");
    if (!container) return;

    let serverTransactions = [];
    const render = transactions => {
        container.replaceChildren();
        container.setAttribute("aria-busy", "false");
        delete container.dataset.state;
        if (!transactions.length) {
            const empty = document.createElement("p");
            empty.className = "empty-state";
            empty.textContent = "No transactions recorded on this phone yet.";
            container.appendChild(empty);
            return;
        }
        for (const item of transactions.slice(0, 20)) {
            const row = document.createElement("div");
            row.className = "transaction-row";
            const title = document.createElement("strong");
            const isOfflineReceipt = item.status === "payment_sent_simulation" ||
                item.status === "payment_received_simulation" ||
                item.status === "accepted_for_simulation_review" ||
                item.status === "pending_reconciliation";
            title.textContent = isOfflineReceipt
                ? "Offline payment"
                : (item.transaction_id || item.id || "Offline transaction");
            const detail = document.createElement("span");
            const amount = item.amount ?? (item.amount_paise !== undefined ? Number(item.amount_paise) / 100 : null);
            detail.textContent = `${formatINR(amount)} · ${formatTransactionStatus(item)}`;
            row.append(title, detail);
            container.appendChild(row);
        }
    };

    render(NetBridgeOfflineStore.getTransactions(CUSTOMER_ID));
    if (!navigator.onLine) return NetBridgeOfflineStore.getTransactions(CUSTOMER_ID);
    try {
        const response = await fetchWithTimeout(
            `/api/wallets/${encodeURIComponent(CUSTOMER_ID)}/transactions`,
            { method: "GET", cache: "no-store" },
            2500
        );

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(data.error || "Unable to load transaction history.");
        }

        serverTransactions = Array.isArray(data.transactions) ? data.transactions : [];
    } catch (error) {
        console.info("Using local customer transaction history:", error.message);
    }

    const transactions = NetBridgeOfflineStore.getTransactions(CUSTOMER_ID, serverTransactions);
    render(transactions);
    return transactions;
}

function renderPendingFarPayments() {
    const target = byId("farPendingPayments");
    const syncButton = byId("syncFarPaymentsButton");
    if (!target) return;
    const queued = NetBridgeOfflineStore.getPendingFarPayments(CUSTOMER_ID);
    target.replaceChildren();
    if (syncButton) syncButton.hidden = queued.length === 0;
    for (const payment of queued) {
        const item = document.createElement("p");
        item.className = "message";
        item.dataset.state = "info";
        item.textContent = `${formatINR(payment.amount_paise / 100)} to ${payment.recipient_upi_id} · Pending. Recipient has not received it.`;
        target.appendChild(item);
    }
}

function newFarPaymentId() {
    if (window.crypto?.randomUUID) return `far-${window.crypto.randomUUID()}`;
    const bytes = window.crypto.getRandomValues(new Uint8Array(20));
    return `far-${Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("")}`;
}

async function syncPendingFarPayments(pin) {
    if (farPaymentSyncInProgress) return;
    if (!navigator.onLine) {
        showMessage("farPaymentMessage", "Still offline. The transfer remains pending on this phone; the receiver has not received it.", "info");
        return;
    }
    const queued = NetBridgeOfflineStore.getPendingFarPayments(CUSTOMER_ID);
    if (!queued.length) {
        renderPendingFarPayments();
        showMessage("farPaymentMessage", "There are no pending far payments to sync.", "info");
        return;
    }
    if (!/^\d{4}$/.test(pin || "")) {
        showMessage("farPaymentMessage", "Enter your four-digit customer demo PIN to sync the pending transfer.", "error");
        return;
    }

    farPaymentSyncInProgress = true;
    const syncButton = byId("syncFarPaymentsButton");
    if (syncButton) syncButton.disabled = true;
    try {
        for (const payment of queued) {
            const result = await apiPost("/api/far-payments", {
                sender_id: CUSTOMER_ID,
                recipient_upi_id: payment.recipient_upi_id,
                amount_paise: payment.amount_paise,
                transaction_id: payment.transaction_id,
                pin
            });
            NetBridgeOfflineStore.completeFarPayment(
                CUSTOMER_ID,
                payment.transaction_id,
                Number(result.sender_balance_paise)
            );
            NetBridgePaymentFeedback.paymentSent();
        }
        pendingFarSyncPin = null;
        if (byId("farPaymentPin")) byId("farPaymentPin").value = "";
        renderPendingFarPayments();
        await Promise.all([loadCustomerWallet(), loadCustomerHistory()]);
        showMessage("farPaymentMessage", "Pending payment delivered to the recipient's NetBridge demo wallet.", "success");
    } catch (error) {
        showMessage("farPaymentMessage", `${error.message} The transfer remains pending; the receiver has not received it.`, "error");
    } finally {
        farPaymentSyncInProgress = false;
        if (syncButton) syncButton.disabled = false;
    }
}

async function submitFarPayment(event) {
    event.preventDefault();
    const recipient = (byId("farRecipientId")?.value || "").trim().toLowerCase();
    const amountText = (byId("farPaymentAmount")?.value || "").trim();
    const pin = (byId("farPaymentPin")?.value || "").trim();
    const otp = (byId("farPaymentOtp")?.value || "").trim();
    const button = byId("farPaymentSubmit");
    if (recipient !== "merchant@netbridge" && recipient !== "customer2@netbridge") {
        showMessage("farPaymentMessage", "Enter a registered demo ID: merchant@netbridge or customer2@netbridge.", "error");
        return;
    }
    const amount = Number(amountText);
    const amountPaise = Math.round(amount * 100);
    if (!Number.isFinite(amount) || amountPaise <= 0 || amount > 5000 || Math.abs(amount * 100 - amountPaise) > 0.0001) {
        showMessage("farPaymentMessage", "Enter an amount from ₹0.01 to ₹5,000.00.", "error");
        return;
    }
    if (!/^\d{4}$/.test(pin)) {
        showMessage("farPaymentMessage", "Enter your four-digit customer demo PIN.", "error");
        return;
    }
    if (!/^\d{6}$/.test(otp)) {
        showMessage("farPaymentMessage", "Enter the current six-digit Authenticator code.", "error");
        return;
    }
    if (!pageAuthenticatorConnected) {
        showMessage("farPaymentMessage", "Connect Authenticator before sending a far payment.", "error");
        openAuthenticatorModal();
        return;
    }
    if (NetBridgeOfflineStore.getBalance(CUSTOMER_ID) < amountPaise) {
        showMessage("farPaymentMessage", "The local demo wallet has insufficient balance.", "error");
        return;
    }

    NetBridgePaymentFeedback.unlockAudio();
    if (button) button.disabled = true;
    try {
        const otpValid = await NetBridgeOfflineTOTP.verifyAndConsume(CUSTOMER_ID, pin, otp);
        if (!otpValid) throw new Error("Authenticator code is incorrect, expired, or already used. Wait for the next code.");
        const payment = {
            recipient_upi_id: recipient,
            amount_paise: amountPaise,
            transaction_id: newFarPaymentId(),
            created_at: Math.floor(Date.now() / 1000)
        };

        if (navigator.onLine) {
            try {
                const result = await apiPost("/api/far-payments", {
                    sender_id: CUSTOMER_ID,
                    recipient_upi_id: recipient,
                    amount_paise: amountPaise,
                    transaction_id: payment.transaction_id,
                    pin
                });
                NetBridgeOfflineStore.seedFromServer(CUSTOMER_ID, Number(result.sender_balance_paise));
                NetBridgePaymentFeedback.paymentSent();
                await Promise.all([loadCustomerWallet(), loadCustomerHistory()]);
                showMessage("farPaymentMessage", `Payment delivered to ${recipient}. Receiver needs no code or QR scan.`, "success");
            } catch (error) {
                if (!(error instanceof TypeError) && error?.name !== "AbortError") throw error;
                NetBridgeOfflineStore.queueFarPayment(CUSTOMER_ID, payment);
                pendingFarSyncPin = pin;
                renderPendingFarPayments();
                showMessage("farPaymentMessage", "Connection to NetBridge was lost. Payment is queued on this phone; the recipient has not received it yet.", "info");
            }
        } else {
            NetBridgeOfflineStore.queueFarPayment(CUSTOMER_ID, payment);
            pendingFarSyncPin = pin;
            renderPendingFarPayments();
            showMessage("farPaymentMessage", "Payment queued offline. The recipient has not received it. NetBridge will sync it when this phone can reach the server.", "info");
        }
        if (byId("farPaymentAmount")) byId("farPaymentAmount").value = "";
        if (byId("farPaymentOtp")) byId("farPaymentOtp").value = "";
        if (byId("farPaymentPin")) byId("farPaymentPin").value = "";
        if (NetBridgeOfflineStore.getPendingFarPayments(CUSTOMER_ID).length) {
            await loadCustomerWallet();
            if (navigator.onLine) void syncPendingFarPayments(pendingFarSyncPin || pin);
        }
    } catch (error) {
        showMessage("farPaymentMessage", error.message, "error");
        if (byId("farPaymentOtp")) byId("farPaymentOtp").value = "";
    } finally {
        if (button) button.disabled = false;
    }
}

function watchForMerchantReceipt(receiptId) {
    // The devices cannot confirm one another after the customer shows the QR
    // without a return communication channel. The outgoing record is saved locally.
    void receiptId;
}

/* ==========================================
   GOOGLE AUTHENTICATOR MODAL
========================================== */

function openAuthenticatorModal() {
    const modal = byId("authenticatorModal");

    if (!modal) {
        console.error("Authenticator modal not found.");
        return;
    }

    modal.hidden = false;

    document.body.classList.add("auth-modal-open");

    if (!pageAuthenticatorConnected) {
        setAuthenticatorView("connect");
    }

    byId("authenticatorPin")?.focus();
}

function closeAuthenticatorModal() {
    const modal = byId("authenticatorModal");

    if (!modal) return;

    modal.hidden = true;

    document.body.classList.remove("auth-modal-open");
}

function setAuthenticatorView(view) {
    const ids = {
        connect: "authenticatorConnectPanel",
        setup: "authenticatorSetupPanel",
        connected: "authenticatorConnectedPanel"
    };

    Object.entries(ids).forEach(([key, id]) => {
        const element = byId(id);

        if (element) {
            element.hidden = key !== view;
        }
    });
}

function markAuthenticatorConnected(message) {
    pageAuthenticatorConnected = true;
    try { localStorage.setItem(AUTHENTICATOR_CONNECTED_KEY, "true"); } catch (_) {}
    pendingAuthenticatorPin = null;
    pendingAuthenticatorSecret = null;
    pendingAuthenticatorLocalOnly = false;
    setAuthenticatorView("connected");
    setText("authenticatorStatusText", "✓ Authenticator ready for offline verification.");
    showMessage("authenticatorMessage", message, "success");
}

async function connectAuthenticator() {
    const pin = (byId("authenticatorPin")?.value || "").trim();
    if (!/^\d{4}$/.test(pin)) {
        showMessage("authenticatorMessage", "Enter your 4-digit customer wallet PIN.", "error");
        return;
    }

    const button = byId("connectAuthenticatorButton");
    if (button) button.disabled = true;

    try {
        if (localStorage.getItem(AUTHENTICATOR_REFRESH_KEY) === "true") {
            if (!navigator.onLine) throw new TypeError("Authenticator refresh requires a connection to the NetBridge server.");
            await apiPost("/api/authenticator/refresh", { user_id: CUSTOMER_ID, pin });
            localStorage.removeItem(AUTHENTICATOR_REFRESH_KEY);
            localStorage.removeItem(OFFLINE_CREDENTIAL_KEY);
            localStorage.removeItem(AUTHENTICATOR_CONNECTED_KEY);
            pendingAuthenticatorPin = pin;
            pendingAuthenticatorLocalOnly = false;
            pageAuthenticatorConnected = false;
            if (byId("authenticatorExistingOtpPanel")) byId("authenticatorExistingOtpPanel").hidden = true;
            if (byId("authenticatorExistingOtp")) byId("authenticatorExistingOtp").value = "";
            setAuthenticatorView("setup");
            await generateAuthenticatorQr();
            return;
        }
        if (localStorage.getItem(OFFLINE_CREDENTIAL_KEY)) {
            const otpPanel = byId("authenticatorExistingOtpPanel");
            const otp = (byId("authenticatorExistingOtp")?.value || "").trim();
            if (otpPanel) otpPanel.hidden = false;
            if (!/^\d{6}$/.test(otp)) {
                showMessage("authenticatorMessage", "Enter a current six-digit Authenticator code to unlock this phone's offline setup.", "info");
                return;
            }
            const credential = await NetBridgeOfflineTOTP.loadCredential(CUSTOMER_ID, pin);
            const counter = await NetBridgeOfflineTOTP.verifyCode(
                credential.secret, otp, Date.now(), 1, -1
            );
            if (counter === null) throw new Error("Authenticator code is incorrect or expired. Enter the current code and try again.");
            if (byId("authenticatorExistingOtp")) byId("authenticatorExistingOtp").value = "";
            if (otpPanel) otpPanel.hidden = true;
            markAuthenticatorConnected("Authenticator verified on this phone. Payment codes are still limited to one use.");
            setTimeout(closeAuthenticatorModal, 500);
            return;
        }

        if (!navigator.onLine) throw new TypeError("Offline mode");
        const result = await apiPost("/api/authenticator/status", {
            user_id: CUSTOMER_ID,
            pin
        });
        if (result.status !== "success") {
            throw new Error(result.message || "Wallet verification failed.");
        }

        pendingAuthenticatorPin = pin;
        if (result.authenticator_enabled === true) {
            const otpPanel = byId("authenticatorExistingOtpPanel");
            if (otpPanel) otpPanel.hidden = false;
            const otp = (byId("authenticatorExistingOtp")?.value || "").trim();
            if (!/^\d{6}$/.test(otp)) {
                setAuthenticatorView("connect");
                showMessage("authenticatorMessage", "Enter one current Authenticator code, then connect again to prepare offline verification.", "info");
                return;
            }

            const credential = await apiPost("/api/authenticator/offline-credential", {
                user_id: CUSTOMER_ID,
                pin,
                otp
            });
            const counter = await NetBridgeOfflineTOTP.verifyCode(
                credential.offline_secret, otp, Date.now(), 1, -1
            );
            if (counter === null) {
                throw new Error("Authenticator code could not be prepared for offline use. Try the next code.");
            }
            await NetBridgeOfflineTOTP.saveCredential(CUSTOMER_ID, pin, credential.offline_secret, -1);
            if (otpPanel) otpPanel.hidden = true;
            if (byId("authenticatorExistingOtp")) byId("authenticatorExistingOtp").value = "";
            markAuthenticatorConnected("Authenticator verified. Future payment codes will be checked on this phone while offline.");
            return;
        }

        pageAuthenticatorConnected = false;
        try { localStorage.removeItem(AUTHENTICATOR_CONNECTED_KEY); } catch (_) {}
        const otpPanel = byId("authenticatorExistingOtpPanel");
        if (otpPanel) otpPanel.hidden = true;
        setAuthenticatorView("setup");
        showMessage("authenticatorMessage", "Wallet verified. Preparing Authenticator enrollment...", "success");
        await generateAuthenticatorQr();
    } catch (error) {
        if (isNetworkFailure(error)) {
            pendingAuthenticatorPin = pin;
            pendingAuthenticatorLocalOnly = true;
            setAuthenticatorView("setup");
            showMessage("authenticatorMessage", "No server connection. Preparing a new Authenticator secret on this phone for this demo wallet.", "info");
            await generateAuthenticatorQr();
        } else {
            showMessage("authenticatorMessage", error.message, "error");
        }
    } finally {
        if (button) button.disabled = false;
        const pinInput = byId("authenticatorPin");
        if (pinInput) pinInput.value = "";
    }
}

/* ==========================================
   AUTHENTICATOR QR GENERATION
========================================== */

async function generateAuthenticatorQr() {
    if (!pendingAuthenticatorPin) {
        showMessage(
            "authenticatorMessage",
            "Verify your wallet PIN first.",
            "error"
        );

        setAuthenticatorView("connect");
        return;
    }

    const button = byId("generateAuthenticatorButton");

    if (button) button.disabled = true;

    try {
        if (pendingAuthenticatorLocalOnly) {
            pendingAuthenticatorSecret = NetBridgeOfflineTOTP.generateSecret();
            renderAuthenticatorSetupQr(pendingAuthenticatorSecret);
            showMessage("authenticatorMessage", "Local-only setup: scan this QR, then enter a six-digit code. Keep the secret private.", "success");
            return;
        }

        if (!navigator.onLine) throw new TypeError("Offline mode");

        const result = await apiPost(
            "/api/authenticator/enroll",
            {
                user_id: CUSTOMER_ID,
                pin: pendingAuthenticatorPin
            }
        );

        if (
            result.status !== "success" ||
            !result.qr_code ||
            !result.qr_code.startsWith("data:image/png;base64,") ||
            typeof result.offline_secret !== "string"
        ) {
            throw new Error(
                result.message ||
                "Authenticator QR generation failed."
            );
        }

        const container = byId("authenticator-qr-container");

        if (!byId("authenticator-qr") || !container) {
            throw new Error(
                "Authenticator QR elements are missing."
            );
        }

        pendingAuthenticatorSecret = result.offline_secret;
        renderAuthenticatorSetupQr(result.offline_secret, result.qr_matrix);
        container.hidden = false;

        showMessage(
            "authenticatorMessage",
            "Scan the QR using Google Authenticator, then enter its six-digit code.",
            "success"
        );

    } catch (error) {
        if (isNetworkFailure(error)) {
            pendingAuthenticatorLocalOnly = true;
            pendingAuthenticatorSecret = NetBridgeOfflineTOTP.generateSecret();
            renderAuthenticatorSetupQr(pendingAuthenticatorSecret);
            showMessage("authenticatorMessage", "Local-only setup: scan this QR, then enter a six-digit code. Keep the secret private.", "success");
        } else {
            showMessage("authenticatorMessage", error.message, "error");
        }

    } finally {
        if (button) button.disabled = false;
    }
}

function renderAuthenticatorSetupQr(secret, serverMatrix = null) {
    const target = byId("authenticator-qr");
    const container = byId("authenticator-qr-container");
    if (!target || !container) throw new Error("Authenticator QR elements are missing.");
    target.replaceChildren();
    target.removeAttribute("title");
    const label = encodeURIComponent(`NetBridge:${CUSTOMER_ID}`);
    const uri = `otpauth://totp/${label}?secret=${secret}&issuer=NetBridge&algorithm=SHA1&digits=6&period=30`;

    // Online enrollment gets its QR modules from Flask. Offline setup falls
    // back to the bundled encoder. Drawing cells avoids canvas and image URLs.
    let rows = serverMatrix;
    if (!Array.isArray(rows)) {
        if (typeof window.QRCode !== "function") {
            throw new Error("The offline QR generator is unavailable. Open NetBridge once while its server is running to cache the app files.");
        }
        const scratch = document.createElement("div");
        const generator = new QRCode(scratch, {
            text: uri,
            width: 240,
            height: 240,
            correctLevel: QRCode.CorrectLevel.M
        });
        const matrix = generator._oQRCode;
        if (!matrix || typeof matrix.getModuleCount !== "function" || typeof matrix.isDark !== "function") {
            throw new Error("The Authenticator QR could not be generated. Refresh the page and try again.");
        }
        const count = matrix.getModuleCount();
        rows = Array.from({ length: count }, (_, row) =>
            Array.from({ length: count }, (_, column) => matrix.isDark(row, column) ? "1" : "0").join("")
        );
    }

    const moduleCount = rows.length;
    if (!moduleCount || moduleCount > 177 || rows.some(row => typeof row !== "string" || row.length !== moduleCount || /[^01]/.test(row))) {
        throw new Error("The Authenticator QR data is invalid. Refresh the page and try again.");
    }

    const table = document.createElement("table");
    table.setAttribute("aria-hidden", "true");
    table.style.width = "240px";
    table.style.height = "240px";
    table.style.maxWidth = "100%";
    table.style.tableLayout = "fixed";
    table.style.borderCollapse = "collapse";
    table.style.backgroundColor = "#fff";
    table.style.margin = "0 auto";
    const body = document.createElement("tbody");
    for (let row = 0; row < moduleCount; row += 1) {
        const tableRow = document.createElement("tr");
        for (let column = 0; column < moduleCount; column += 1) {
            const cell = document.createElement("td");
            cell.style.padding = "0";
            cell.style.border = "0";
            cell.style.backgroundColor = rows[row][column] === "1" ? "#000" : "#fff";
            tableRow.appendChild(cell);
        }
        body.appendChild(tableRow);
    }
    table.appendChild(body);
    target.appendChild(table);
    const secretCode = byId("authenticator-secret-code");
    if (secretCode) secretCode.textContent = secret.match(/.{1,4}/g)?.join(" ") || secret;
    container.hidden = false;
}

/* ==========================================
   AUTHENTICATOR OTP VERIFICATION
========================================== */

async function confirmAuthenticator() {
    const otp = (
        byId("authenticatorOtp")?.value || ""
    ).trim();

    if (!/^\d{6}$/.test(otp)) {
        showMessage(
            "authenticatorMessage",
            "Enter the current 6-digit code from Google Authenticator.",
            "error"
        );

        return;
    }

    if (!pendingAuthenticatorPin) {
        showMessage(
            "authenticatorMessage",
            "Your wallet session expired. Connect again.",
            "error"
        );

        setAuthenticatorView("connect");
        return;
    }

    const button = byId("confirmAuthenticatorButton");

    if (button) button.disabled = true;

    try {
        if (pendingAuthenticatorLocalOnly) {
            const counter = await NetBridgeOfflineTOTP.verifyCode(
                pendingAuthenticatorSecret, otp, Date.now(), 1, -1
            );
            if (counter === null) throw new Error("That Authenticator code is incorrect or expired. Enter the current code and try again.");
            await NetBridgeOfflineTOTP.saveCredential(
                CUSTOMER_ID, pendingAuthenticatorPin, pendingAuthenticatorSecret, -1
            );
            pendingAuthenticatorLocalOnly = false;
            markAuthenticatorConnected("Local Authenticator setup saved on this phone. This current code can authorize one payment.");
            byId("authenticator-qr-container").hidden = true;
            showMessage("authenticatorMessage", "Local Authenticator setup complete. Keep the secret private; this demo account exists only on this phone.", "success");
            setTimeout(closeAuthenticatorModal, 1200);
            return;
        }

        if (!navigator.onLine) throw new TypeError("Offline mode");

        const result = await apiPost(
            "/api/authenticator/confirm",
            {
                user_id: CUSTOMER_ID,
                pin: pendingAuthenticatorPin,
                otp: otp
            }
        );

        if (
            result.status !== "success" ||
            result.authenticator_enabled !== true
        ) {
            throw new Error(
                result.message ||
                "Authenticator verification failed."
            );
        }

        if (!pendingAuthenticatorSecret) {
            throw new Error("Offline Authenticator setup is missing. Reconnect and enroll again.");
        }
        const matchedCounter = await NetBridgeOfflineTOTP.verifyCode(
            pendingAuthenticatorSecret, otp, Date.now(), 1, -1
        );
        if (matchedCounter === null) {
            throw new Error("Authenticator code was confirmed by the server but could not be prepared locally. Try the next code.");
        }
        await NetBridgeOfflineTOTP.saveCredential(
            CUSTOMER_ID, pendingAuthenticatorPin, pendingAuthenticatorSecret, -1
        );
        markAuthenticatorConnected("Authenticator connected. Payment PIN and OTP will be checked locally on this phone.");

        const qrContainer = byId(
            "authenticator-qr-container"
        );

        if (qrContainer) {
            qrContainer.hidden = true;
        }

        showMessage(
            "authenticatorMessage",
            "Google Authenticator connected successfully.",
            "success"
        );

        setTimeout(() => {
            closeAuthenticatorModal();
        }, 1200);

    } catch (error) {
        if (isNetworkFailure(error) && pendingAuthenticatorSecret && pendingAuthenticatorPin) {
            const counter = await NetBridgeOfflineTOTP.verifyCode(
                pendingAuthenticatorSecret, otp, Date.now(), 1, -1
            );
            if (counter === null) {
                showMessage("authenticatorMessage", "That Authenticator code is incorrect or expired. Enter the current code and try again.", "error");
            } else {
                await NetBridgeOfflineTOTP.saveCredential(
                    CUSTOMER_ID, pendingAuthenticatorPin, pendingAuthenticatorSecret, -1
                );
                markAuthenticatorConnected("Authenticator setup saved on this phone for offline demo payments.");
                byId("authenticator-qr-container").hidden = true;
                setTimeout(closeAuthenticatorModal, 1000);
            }
        } else {
            showMessage("authenticatorMessage", error.message, "error");
        }

    } finally {
        if (button) button.disabled = false;

        const otpInput = byId("authenticatorOtp");

        if (otpInput) otpInput.value = "";
    }
}

/* ==========================================
   AUTHENTICATOR MODAL EVENTS
========================================== */

function initializeAuthenticatorModal() {

    byId("openAuthenticatorButton")
        ?.addEventListener(
            "click",
            openAuthenticatorModal
        );

    byId("closeAuthenticatorModal")
        ?.addEventListener(
            "click",
            closeAuthenticatorModal
        );

    byId("connectAuthenticatorButton")
        ?.addEventListener(
            "click",
            connectAuthenticator
        );

    byId("generateAuthenticatorButton")
        ?.addEventListener(
            "click",
            generateAuthenticatorQr
        );

    byId("confirmAuthenticatorButton")
        ?.addEventListener(
            "click",
            confirmAuthenticator
        );

    byId("authenticatorModal")
        ?.addEventListener("click", event => {

            if (
                event.target.classList.contains(
                    "auth-modal-backdrop"
                )
            ) {
                closeAuthenticatorModal();
            }
        });

    document.addEventListener("keydown", event => {

        if (
            event.key === "Escape" &&
            !byId("authenticatorModal")?.hidden
        ) {
            closeAuthenticatorModal();
        }
    });
}

/* ==========================================
   QR PAYLOAD PARSING
========================================== */

function parseNetBridgeQr(rawText) {
    let envelope;

    try {
        envelope = JSON.parse(rawText);

    } catch {
        throw new Error(
            "This QR does not contain valid NetBridge JSON data."
        );
    }

    if (
        !envelope ||
        typeof envelope !== "object" ||
        Array.isArray(envelope)
    ) {
        throw new Error("Invalid QR payload.");
    }

    if (
        envelope.type !== "payment_request" ||
        !envelope.data ||
        typeof envelope.data !== "object"
    ) {
        throw new Error(
            "This is not a NetBridge merchant payment-request QR."
        );
    }

    const request = envelope.data.request;

    if (!request || typeof request !== "object") {
        throw new Error(
            "The merchant payment request is incomplete."
        );
    }

    const merchantId = String(
        request.merchant_user_id || ""
    ).trim();

    const deviceId = String(
        request.merchant_device_id || ""
    ).trim();

    const amountPaise = Number(
        request.amount_paise
    );

    if (
        !merchantId ||
        !deviceId ||
        !Number.isSafeInteger(amountPaise) ||
        amountPaise <= 0
    ) {
        throw new Error(
            "The QR is missing a valid merchant, device or amount."
        );
    }

    return {
        envelope,
        merchantId,
        deviceId,
        amount: amountPaise / 100
    };
}

/* ==========================================
   IMAGE QR DECODING
========================================== */

async function decodeImageWithBarcodeDetector(file) {
    if (!("BarcodeDetector" in window)) {
        return null;
    }

    try {
        const formats = await BarcodeDetector.getSupportedFormats();

        if (!formats.includes("qr_code")) {
            return null;
        }

        const detector = new BarcodeDetector({
            formats: ["qr_code"]
        });

        const bitmap = await createImageBitmap(file);

        try {
            const codes = await detector.detect(bitmap);

            return codes.length
                ? codes[0].rawValue
                : null;

        } finally {
            bitmap.close();
        }

    } catch (error) {
        console.warn(
            "Native QR decoder unavailable:",
            error
        );

        return null;
    }
}

async function decodeImageWithJsQR(file) {
    if (typeof window.jsQR !== "function") {
        throw new Error(
            "QR decoder is not available in the cached app. Open NetBridge once while the server is available, then reload."
        );
    }

    const bitmap = await createImageBitmap(file);

    try {
        const canvas = document.createElement("canvas");

        const context = canvas.getContext(
            "2d",
            { willReadFrequently: true }
        );

        const scale = Math.min(
            1,
            1800 / Math.max(bitmap.width, bitmap.height)
        );

        canvas.width = Math.max(
            1,
            Math.round(bitmap.width * scale)
        );

        canvas.height = Math.max(
            1,
            Math.round(bitmap.height * scale)
        );

        context.drawImage(
            bitmap,
            0,
            0,
            canvas.width,
            canvas.height
        );

        const imageData = context.getImageData(
            0,
            0,
            canvas.width,
            canvas.height
        );

        const result = window.jsQR(
            imageData.data,
            imageData.width,
            imageData.height,
            {
                inversionAttempts: "attemptBoth"
            }
        );

        return result ? result.data : null;

    } finally {
        bitmap.close();
    }
}

async function decodeQrImage(file) {
    if (!file) {
        throw new Error("Choose a QR image first.");
    }

    if (
        ![
            "image/png",
            "image/jpeg",
            "image/webp"
        ].includes(file.type)
    ) {
        throw new Error(
            "Use a PNG, JPG, JPEG or WEBP image."
        );
    }

    if (file.size > MAX_QR_IMAGE_BYTES) {
        throw new Error(
            "The QR image must be smaller than 5 MB."
        );
    }

    showMessage(
        "customerQrMessage",
        "Decoding QR image..."
    );

    const preview = byId("customerQrPreview");

    if (preview) {
        const imageUrl = URL.createObjectURL(file);

        preview.replaceChildren();

        const image = document.createElement("img");

        image.src = imageUrl;
        image.alt = "Uploaded merchant QR preview";

        image.style.cssText =
            "display:block;max-width:220px;max-height:220px;margin:12px 0;border-radius:8px;";

        image.onload = () => {
            URL.revokeObjectURL(imageUrl);
        };

        preview.appendChild(image);
    }

    let raw = await decodeImageWithBarcodeDetector(file);

    if (!raw) {
        raw = await decodeImageWithJsQR(file);
    }

    if (!raw) {
        throw new Error(
            "No readable QR code was found. Use a clear, uncropped merchant QR image."
        );
    }

    displayMerchantRequest(raw);
}

function displayMerchantRequest(raw) {
    const parsed = parseNetBridgeQr(raw);
    NetBridgePaymentFeedback.qrDetected();

    decodedMerchantQrText = raw;
    decodedMerchantQrPayload = parsed.envelope;
    paymentCompleted = false;

    setText("qrMerchantId", parsed.merchantId);
    setText("qrReceiverDevice", parsed.deviceId);
    setText("qrPaymentAmount", formatINR(parsed.amount));

    const details = byId("customerPaymentDetails");

    if (details) {
        details.hidden = false;
    }

    // Keep legacy second-QR controls hidden if an older HTML template remains.
    const legacyAuthorizationSection = byId("customerAuthorizationQr");
    if (legacyAuthorizationSection) legacyAuthorizationSection.hidden = true;

    const legacyDownloadButton = byId("downloadAuthorizationQrButton");
    if (legacyDownloadButton) legacyDownloadButton.hidden = true;

    if (byId("qrCustomerPin")) {
        byId("qrCustomerPin").value = "";
    }

    if (byId("paymentAuthenticatorOtp")) {
        byId("paymentAuthenticatorOtp").value = "";
    }

    if (byId("approveCustomerPayment")) {
        byId("approveCustomerPayment").checked = false;
    }

    if (byId("authorizeCustomerPaymentButton")) {
        byId("authorizeCustomerPaymentButton").disabled = true;
    }

    showMessage(
        "customerQrMessage",
        "QR decoded. Review the merchant and amount before authorizing the payment.",
        "success"
    );
}

function clearMerchantRequest() {
    decodedMerchantQrText = null;
    decodedMerchantQrPayload = null;
    paymentCompleted = false;

    if (byId("customerPaymentDetails")) {
        byId("customerPaymentDetails").hidden = true;
    }
}

/* ==========================================
   CAMERA SCANNER
========================================== */

function stopCameraScanner() {
    if (cameraFrameHandle !== null) {
        cancelAnimationFrame(cameraFrameHandle);
        cameraFrameHandle = null;
    }

    if (cameraStream) {
        cameraStream.getTracks().forEach(track => {
            track.stop();
        });

        cameraStream = null;
    }

    const video = byId("qrCamera");
    const preview = byId("qrScannerPreview");

    if (video) {
        video.pause();
        video.srcObject = null;
        preview?.classList.remove("is-active");
    }

    if (byId("startQrCameraButton")) {
        byId("startQrCameraButton").disabled = false;
    }

    if (byId("stopQrCameraButton")) {
        byId("stopQrCameraButton").disabled = true;
    }
}

async function startCameraScanner() {
    if (
        !navigator.mediaDevices ||
        !navigator.mediaDevices.getUserMedia
    ) {
        showMessage(
            "customerQrMessage",
            "Camera unavailable. Open NetBridge using localhost or HTTPS.",
            "error"
        );

        return;
    }

    const nativeQrAvailable = "BarcodeDetector" in window;

    const jsQrAvailable =
        typeof window.jsQR === "function";

    if (!nativeQrAvailable && !jsQrAvailable) {
        showMessage(
            "customerQrMessage",
            "No QR decoder is available in this browser. Use a browser with BarcodeDetector support or load the local jsQR decoder.",
            "error"
        );

        return;
    }

    try {
        cameraStream =
            await navigator.mediaDevices.getUserMedia({
                audio: false,
                video: {
                    facingMode: {
                        ideal: "environment"
                    },
                    width: {
                        ideal: 1280
                    },
                    height: {
                        ideal: 720
                    }
                }
            });

        const video = byId("qrCamera");

        if (!video) {
            throw new Error("Camera video element is missing.");
        }

        video.srcObject = cameraStream;
        byId("qrScannerPreview")?.classList.add("is-active");

        await video.play();

        byId("startQrCameraButton").disabled = true;
        byId("stopQrCameraButton").disabled = false;

        showMessage(
            "customerQrMessage",
            "Camera active. Point it towards the merchant QR code."
        );

        const canvas = document.createElement("canvas");

        const context = canvas.getContext(
            "2d",
            { willReadFrequently: true }
        );

        const detector = nativeQrAvailable
            ? new BarcodeDetector({
                formats: ["qr_code"]
            })
            : null;

        let scanning = true;
        let lastScanTime = 0;
        let detectionInProgress = false;

        const scanFrame = async () => {
            if (!scanning || !cameraStream) {
                return;
            }

            if (
                video.readyState >= 2 &&
                video.videoWidth > 0 &&
                video.videoHeight > 0
            ) {
                const now = Date.now();

                if (
                    now - lastScanTime >= 180 &&
                    !detectionInProgress
                ) {
                    lastScanTime = now;
                    detectionInProgress = true;

                    try {
                        let decodedText = null;

                        if (detector) {
                            const detections =
                                await detector.detect(video);

                            if (detections.length) {
                                decodedText =
                                    detections[0].rawValue;
                            }
                        }

                        if (!decodedText && jsQrAvailable) {
                            canvas.width = video.videoWidth;
                            canvas.height = video.videoHeight;

                            context.drawImage(
                                video,
                                0,
                                0,
                                canvas.width,
                                canvas.height
                            );

                            const pixels =
                                context.getImageData(
                                    0,
                                    0,
                                    canvas.width,
                                    canvas.height
                                );

                            const result = window.jsQR(
                                pixels.data,
                                pixels.width,
                                pixels.height,
                                {
                                    inversionAttempts: "attemptBoth"
                                }
                            );

                            if (result) {
                                decodedText = result.data;
                            }
                        }

                        if (decodedText) {
                            scanning = false;

                            stopCameraScanner();

                            try {
                                displayMerchantRequest(decodedText);

                            } catch (error) {
                                showMessage(
                                    "customerQrMessage",
                                    error.message,
                                    "error"
                                );
                            }

                            return;
                        }

                    } catch (scanError) {
                        console.debug(
                            "QR frame not decoded:",
                            scanError
                        );

                    } finally {
                        detectionInProgress = false;
                    }
                }
            }

            if (scanning && cameraStream) {
                cameraFrameHandle =
                    requestAnimationFrame(scanFrame);
            }
        };

        cameraFrameHandle =
            requestAnimationFrame(scanFrame);

    } catch (error) {
        console.error("Camera error:", error);

        stopCameraScanner();

        showMessage(
            "customerQrMessage",
            error.name === "NotAllowedError"
                ? "Camera permission denied. Allow camera access in your browser."
                : error.name === "NotFoundError"
                    ? "No camera was detected on this device."
                    : "Unable to open camera: " + error.message,
            "error"
        );
    }
}

/* ==========================================
   CUSTOMER PAYMENT AUTHORIZATION — MANUAL CODE HANDOFF
========================================== */

async function buildCustomerReceipt(request) {
    const now = Math.floor(Date.now() / 1000);
    const requestExpiry = Number(request.expires_at);
    if (!Number.isSafeInteger(requestExpiry) || requestExpiry <= now) {
        throw new Error("The merchant payment request has expired.");
    }
    const amount = Number(request.amount_paise);
    if (!Number.isSafeInteger(amount) || amount <= 0 || amount > 500000) {
        throw new Error("The merchant payment amount is invalid.");
    }
    const code = await NetBridgeManualReceiptCode.generate(request, CUSTOMER_ID);
    const receipt = {
        receipt_id: code,
        request_id: request.request_id,
        amount_paise: amount,
        created_at: now
    };
    return { code, receipt };
}

async function authorizeCustomerPayment() {
    const pin = (byId("qrCustomerPin")?.value || "").trim();
    const approved = byId("approveCustomerPayment")?.checked === true;
    const otpInput = byId("paymentAuthenticatorOtp");
    const otp = (otpInput?.value || "").trim();
    const button = byId("authorizeCustomerPaymentButton");
    const request = decodedMerchantQrPayload?.data?.request;

    if (!request) return showMessage("qrPaymentMessage", "Scan a merchant payment QR first.", "error");
    if (paymentCompleted) return showMessage("qrPaymentMessage", "A confirmation code has already been generated for this request.", "info");
    if (!/^\d{4}$/.test(pin)) return showMessage("qrPaymentMessage", "Enter your 4-digit customer PIN.", "error");
    if (!approved) return showMessage("qrPaymentMessage", "Approve the merchant and amount first.", "error");
    if (!pageAuthenticatorConnected) {
        showMessage("qrPaymentMessage", "Connect Authenticator before continuing.", "error");
        openAuthenticatorModal();
        return;
    }
    if (!/^\d{6}$/.test(otp)) return showMessage("qrPaymentMessage", "Enter the six-digit Authenticator code.", "error");

    NetBridgePaymentFeedback.unlockAudio();
    if (button) button.disabled = true;
    try {
        const validOtp = await NetBridgeOfflineTOTP.verifyAndConsume(
            CUSTOMER_ID, pin, otp
        );
        if (!validOtp) {
            if (otpInput) otpInput.value = "";
            throw new Error("Authenticator code is incorrect, expired, or already used. Enter the current code and try again.");
        }
        const amountPaise = Number(request.amount_paise);
        if (NetBridgeOfflineStore.getBalance(CUSTOMER_ID) < amountPaise) {
            throw new Error("The local demo wallet has insufficient balance.");
        }
        const payment = await buildCustomerReceipt(request);
        NetBridgeOfflineStore.recordOutgoing(CUSTOMER_ID, amountPaise, payment.receipt);
        paymentCompleted = true;
        NetBridgePaymentFeedback.paymentSent();
        setText("customerReceiptCode", payment.code);
        const panel = byId("customerReceiptPanel");
        if (panel) panel.hidden = false;
        byId("customerBalance").textContent = formatINR(NetBridgeOfflineStore.getBalance(CUSTOMER_ID) / 100);
        loadCustomerHistory();
        if (byId("qrCustomerPin")) byId("qrCustomerPin").value = "";
        if (otpInput) otpInput.value = "";
        showMessage("qrPaymentMessage", "Payment saved on this phone. Show the 10-character confirmation code to the merchant for checking against the active request.", "success");
    } catch (error) {
        showMessage("qrPaymentMessage", error.message, "error");
        if (button) button.disabled = false;
    }
}

/* ==========================================
   CUSTOMER PAGE INITIALIZATION
========================================== */

document.addEventListener("DOMContentLoaded", async () => {
    const authServerRestarted = await syncAuthenticatorServerSession();
    Promise.allSettled([loadCustomerWallet(), loadCustomerHistory()]).finally(hideInitialLoader);
    renderPendingFarPayments();
    if (NetBridgeOfflineStore.getPendingFarPayments(CUSTOMER_ID).length) {
        showMessage("farPaymentMessage", "A far payment is still pending. The receiver has not received it yet.", "info");
    }

    // Reset temporary page state.
    // Require the customer to reconnect Authenticator after each page refresh.
    // Keep the local offline credential intact; the user reconnects with PIN and OTP.
    pageAuthenticatorConnected = false;
    try { localStorage.removeItem(AUTHENTICATOR_CONNECTED_KEY); } catch (_) {}
    pendingAuthenticatorPin = null;
    paymentCompleted = false;
    // Initialize the Authenticator modal.
    initializeAuthenticatorModal();
    setAuthenticatorView(pageAuthenticatorConnected ? "connected" : "connect");
    const existingOtpPanel = byId("authenticatorExistingOtpPanel");
    if (existingOtpPanel && localStorage.getItem(OFFLINE_CREDENTIAL_KEY)) {
        existingOtpPanel.hidden = false;
    }

    // Automatically prompt the customer to connect Authenticator.
    // The customer must still verify their wallet PIN.
    const modal = byId("authenticatorModal");

    if (modal && !pageAuthenticatorConnected) {
        modal.hidden = true;
        document.body.classList.remove("auth-modal-open");

        window.setTimeout(() => {
            if (!pageAuthenticatorConnected) {
                openAuthenticatorModal();

                showMessage(
                    "authenticatorMessage",
                    authServerRestarted
                        ? "The NetBridge server restarted. Enter your PIN to set up a fresh Authenticator connection."
                        : "Connect your Authenticator to secure offline payments.",
                    "info"
                );
            }
        }, 350);
    }

    window.addEventListener("online", () => {
        void refreshCustomerView().finally(() => {
            if (pendingFarSyncPin) void syncPendingFarPayments(pendingFarSyncPin);
        });
    });
    byId("farPaymentForm")?.addEventListener("submit", submitFarPayment);
    byId("syncFarPaymentsButton")?.addEventListener("click", () => {
        void syncPendingFarPayments((byId("farPaymentPin")?.value || "").trim());
    });
    byId("refreshButton")?.addEventListener("click", event => {
        void refreshCustomerView({ button: event.currentTarget });
    });
    let pullStartY = 0;
    let pullDistance = 0;
    const pullIndicator = byId("pullRefreshIndicator");
    document.addEventListener("touchstart", event => {
        if (window.scrollY <= 0 && event.touches.length === 1) pullStartY = event.touches[0].clientY;
        else pullStartY = 0;
    }, { passive: true });
    document.addEventListener("touchmove", event => {
        if (!pullStartY || window.scrollY > 0 || !event.touches.length) return;
        pullDistance = Math.max(0, event.touches[0].clientY - pullStartY);
        if (pullDistance > 16 && pullIndicator) pullIndicator.classList.add("is-visible");
        if (pullIndicator && !pullIndicator.classList.contains("is-refreshing")) {
            const label = pullIndicator.querySelector("span:last-child");
            if (label) label.textContent = pullDistance >= 72 ? "Release to refresh" : "Pull to refresh";
        }
    }, { passive: true });
    document.addEventListener("touchend", () => {
        const shouldRefresh = pullStartY > 0 && pullDistance >= 72 && !pullIndicator?.classList.contains("is-refreshing");
        pullStartY = 0;
        pullDistance = 0;
        if (shouldRefresh) void refreshCustomerView({ pullIndicator: true });
        else if (pullIndicator && !pullIndicator.classList.contains("is-refreshing")) pullIndicator.classList.remove("is-visible");
    }, { passive: true });
    document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") {
            void refreshCustomerView();
            if (pendingFarSyncPin) void syncPendingFarPayments(pendingFarSyncPin);
        }
    });

    // Hide payment details and any legacy second-QR controls on page load.
    if (byId("customerPaymentDetails")) {
        byId("customerPaymentDetails").hidden = true;
    }

    if (byId("customerAuthorizationQr")) {
        byId("customerAuthorizationQr").hidden = true;
    }

    if (byId("downloadAuthorizationQrButton")) {
        byId("downloadAuthorizationQrButton").hidden = true;
    }

    // Merchant QR image upload.
    byId("customerQrUpload")?.addEventListener(
        "change",
        async event => {
            clearMerchantRequest();

            const file = event.target.files?.[0];

            if (!file) {
                return;
            }

            try {
                await decodeQrImage(file);

            } catch (error) {
                showMessage(
                    "customerQrMessage",
                    error.message,
                    "error"
                );
            }
        }
    );

    // Camera scanner controls.
    byId("startQrCameraButton")?.addEventListener(
        "click",
        startCameraScanner
    );

    byId("stopQrCameraButton")?.addEventListener(
        "click",
        stopCameraScanner
    );

    // Enable authorization only after customer approval.
    byId("approveCustomerPayment")?.addEventListener(
        "change",
        event => {
            const button =
                byId("authorizeCustomerPaymentButton");

            if (button) {
                button.disabled =
                    !event.target.checked || paymentCompleted;
            }
        }
    );

    // Payment authorization.
    byId("authorizeCustomerPaymentButton")?.addEventListener(
        "click",
        authorizeCustomerPayment
    );

    // Stop camera when leaving the page.
    window.addEventListener(
        "beforeunload",
        stopCameraScanner
    );
});
