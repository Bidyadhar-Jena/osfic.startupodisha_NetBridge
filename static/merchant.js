"use strict";

const MERCHANT_ID = "MERCHANT001";
const MERCHANT_SESSION_KEY = "netbridge.authenticator.server-session.merchant.v1";
let merchantFarHistoryPrimed = false;
const merchantFarPaymentIds = new Set();

async function resetMerchantDemoForNewServerSession() {
    try {
        const response = await fetch("/api/authenticator/session", { cache: "no-store" });
        if (!response.ok) return;
        const data = await response.json();
        if (typeof data.app_session !== "string" || !data.app_session) return;
        const previous = localStorage.getItem(MERCHANT_SESSION_KEY);
        if (previous !== data.app_session) {
            NetBridgeOfflineStore.resetDemoState(MERCHANT_ID);
        }
        localStorage.setItem(MERCHANT_SESSION_KEY, data.app_session);
    } catch (_) {
        // Preserve device-local demo state when the server is unavailable.
    }
}



/* =========================================
   API AND UI HELPERS
   ========================================= */

async function apiRequest(url, options = {}) {

    const headers = {
        ...(options.body ? {
            "Content-Type": "application/json"
        } : {}),
        ...options.headers
    };

    let response;

    try {
        const controller = new AbortController();
        const timer = window.setTimeout(() => controller.abort(), 2500);
        try {
            response = await fetch(url, {
            ...options,
            headers,
                cache: "no-store",
                signal: controller.signal
            });
        } finally {
            window.clearTimeout(timer);
        }

    } catch {

        throw new Error(
            "Cannot connect to NetBridge. Check that the Flask server is running."
        );

    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {

        throw new Error(
            data.error ||
            data.message ||
            `Request failed with HTTP ${response.status}.`
        );

    }

    return data;
}


function byId(id) {

    return document.getElementById(id);

}


function showMessage(id, message, type = "") {

    const element = byId(id);

    if (element) {
        element.textContent = message;
        element.dataset.state = type || (/\b(error|could not|failed|invalid|incorrect|unavailable|unable|cannot|denied|expired|required|not found|must|wrong|enter|choose)\b/i.test(message) ? "error" : "");
    }

}


function formatINR(value) {

    const amount = Number(value);

    if (!Number.isFinite(amount)) {
        return "Amount unavailable";
    }

    return new Intl.NumberFormat("en-IN", {
        style: "currency",
        currency: "INR",
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(amount);

}


function setButtonLoading(button, loading, loadingText) {

    if (!button) return;

    if (loading) {

        button.dataset.originalText = button.textContent;
        button.textContent = loadingText;
        button.disabled = true;

    } else {

        button.textContent =
            button.dataset.originalText || button.textContent;

        button.disabled = false;

        delete button.dataset.originalText;

    }

}


function setManualReceiptEnabled(enabled) {

    ["manualReceiptCode", "acceptMerchantPin", "acceptCustomerReceiptButton"].forEach(id => {
        const field = byId(id);
        if (field) field.disabled = !enabled;
    });

}


/* =========================================
   MERCHANT WALLET
   ========================================= */

async function loadMerchantBalance() {

    const balanceElement = byId("merchantBalance");
    const button = byId("refreshMerchantBalance");

    if (!balanceElement) return;

    if (button) {
        button.disabled = true;
    }

    balanceElement.textContent = formatINR(NetBridgeOfflineStore.getBalance(MERCHANT_ID) / 100);
    if (!navigator.onLine) {
        showMessage("balanceMessage", "Offline demo balance saved on this PC.");
        if (button) button.disabled = false;
        return;
    }

    try {

        const data = await apiRequest(
            `/api/wallets/${encodeURIComponent(MERCHANT_ID)}/balance`
        );

        const rawBalance =
            data.balance_rupees ??
            data.balance ??
            data.wallet?.balance_rupees ??
            data.wallet?.balance;

        if (
            rawBalance === undefined ||
            rawBalance === null ||
            !Number.isFinite(Number(rawBalance))
        ) {

            throw new Error(
                "The server did not return a valid merchant balance."
            );

        }

        const amountPaise = Math.round(Number(rawBalance) * 100);
        NetBridgeOfflineStore.seedFromServer(MERCHANT_ID, amountPaise);
        balanceElement.textContent = formatINR(NetBridgeOfflineStore.getBalance(MERCHANT_ID) / 100);
        showMessage("balanceMessage", NetBridgeOfflineStore.getPendingDelta(MERCHANT_ID)
            ? "Includes simulated payments saved on this device."
            : "");

    } catch (error) {

        balanceElement.textContent = formatINR(NetBridgeOfflineStore.getBalance(MERCHANT_ID) / 100);
        showMessage("balanceMessage", "Offline demo balance loaded from this PC. It does not sync to another device.");

    } finally {

        if (button) {
            button.disabled = false;
        }

    }

}


/* =========================================
   GENERATE MERCHANT PAYMENT REQUEST QR
   ========================================= */

function isServerUnavailable(error) {
    return !navigator.onLine || error instanceof TypeError ||
        String(error?.message || "").startsWith("Cannot connect to NetBridge");
}

function randomHex(bytes = 16) {
    const data = window.crypto.getRandomValues(new Uint8Array(bytes));
    return Array.from(data, value => value.toString(16).padStart(2, "0")).join("");
}

function createLocalPaymentRequest(amount) {
    const now = Math.floor(Date.now() / 1000);
    const request = {
        request_id: randomHex(),
        nonce: randomHex(),
        merchant_user_id: MERCHANT_ID,
        merchant_device_id: `MERCHANT-OFFLINE-${randomHex(4)}`,
        amount_paise: Math.round(amount * 100),
        currency: "INR",
        created_at: now,
        expires_at: now + 300,
        local_only: true
    };
    const envelope = {
        protocol: "netbridge-offline-v1",
        mode: "simulation_only",
        type: "payment_request",
        data: { request }
    };
    return { request, qr_data: JSON.stringify(envelope) };
}

function makeQrImageData(raw, size = 420) {
    if (typeof window.QRCode !== "function") {
        throw new Error("The QR generator is not cached yet. Open both dashboards once while NetBridge is available, then retry offline.");
    }
    const target = document.createElement("div");
    new QRCode(target, { text: raw, width: size, height: size, correctLevel: QRCode.CorrectLevel.M });
    const canvas = target.querySelector("canvas");
    if (canvas) return canvas.toDataURL("image/png");
    const image = target.querySelector("img");
    if (image?.src) return image.src;
    throw new Error("The local QR image could not be generated.");
}

function restoreActiveMerchantRequest() {
    const raw = NetBridgeOfflineStore.getActiveRequest();
    if (!raw) return;
    try {
        const parsed = JSON.parse(raw);
        const request = parsed?.data?.request;
        if (!request || Number(request.expires_at) <= Math.floor(Date.now() / 1000)) {
            NetBridgeOfflineStore.clearActiveRequest();
            return;
        }
        window.netBridgeMerchantQrData = raw;
        byId("merchantQrImage").src = makeQrImageData(raw);
        byId("generatedAmount").textContent = formatINR(Number(request.amount_paise) / 100);
        byId("qrContainer").hidden = false;
        setManualReceiptEnabled(true);
        showMessage("qrMessage", "Restored the unexpired payment request saved on this device.");
        setManualReceiptEnabled(true);
        showMessage("merchantCodeMessage", "Request restored. Enter the customer's confirmation code.");
    } catch (error) {
        NetBridgeOfflineStore.clearActiveRequest();
        console.warn("Could not restore local merchant request:", error);
    }
}

async function generateMerchantQR(event) {

    event.preventDefault();

    const amountInput = byId("paymentAmount");
    const pinInput = byId("qrMerchantPin");
    const button = byId("generateQrButton");
    const qrContainer = byId("qrContainer");
    const imageElement = byId("merchantQrImage");

    if (!amountInput || !pinInput) {

        showMessage(
            "qrMessage",
            "Payment form is incomplete."
        );

        return;
    }

    const amount = Number(amountInput.value);
    const pin = pinInput.value;

    if (
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > 5000 ||
        Math.round(amount * 100) !== amount * 100
    ) {

        showMessage(
            "qrMessage",
            "Enter an amount between ₹0.01 and ₹5,000.00."
        );

        return;
    }

    if (!/^\d{4}$/.test(pin)) {

        showMessage(
            "qrMessage",
            "Enter your four-digit merchant wallet PIN."
        );

        return;
    }

    setButtonLoading(button, true, "Generating QR...");

    showMessage("qrMessage", "");

    if (qrContainer) {
        qrContainer.hidden = true;
    }

    if (imageElement) {
        imageElement.removeAttribute("src");
    }

    window.netBridgeMerchantQrData = null;

    clearReceiptPreview();

    setManualReceiptEnabled(false);

    try {

        let data;
        let offlineRequest = false;
        try {
            if (!navigator.onLine) throw new TypeError("Offline mode");
            data = await apiRequest(
                "/api/offline/merchant/request",
                {
                    method: "POST",
                    body: JSON.stringify({
                        merchant_id: MERCHANT_ID,
                        pin,
                        amount: amount.toFixed(2)
                    })
                }
            );
            await NetBridgeOfflineStore.merchantPinMatchesOrEnroll(pin, true);
        } catch (error) {
            if (!isServerUnavailable(error)) throw error;
            const local = createLocalPaymentRequest(amount);
            const pinState = await NetBridgeOfflineStore.merchantPinMatchesOrEnroll(pin);
            if (!pinState.matches) throw new Error("Incorrect local merchant demo PIN.");
            data = {
                success: true,
                mode: "simulation_only",
                request: local.request,
                qr_data: local.qr_data,
                qr_image: makeQrImageData(local.qr_data),
                local_offline: true
            };
            offlineRequest = true;
        }

        if (
            data.success !== true ||
            data.mode !== "simulation_only"
        ) {

            throw new Error(
                data.error ||
                data.message ||
                "Merchant payment request could not be created."
            );

        }

        if (typeof data.qr_image !== "string" || !data.qr_image.startsWith("data:image/")) {

            throw new Error(
                "The server did not return a valid payment QR image."
            );

        }

        if (
            typeof data.qr_data !== "string" ||
            !data.qr_data.trim()
        ) {

            throw new Error(
                "The server did not return the payment QR data."
            );

        }

        if (
            !data.request ||
            data.request.request_id === undefined
        ) {

            throw new Error(
                "The server response is missing the payment request details."
            );

        }

        /*
         * Keep the exact request locally so the manually entered code can be
         * checked offline against this merchant's active request.
         */

        window.netBridgeMerchantQrData = data.qr_data;
        NetBridgeOfflineStore.setActiveRequest(data.qr_data);

        imageElement.src = data.qr_image;

        byId("generatedAmount").textContent =
            formatINR(Number(data.request.amount_paise) / 100);

        qrContainer.hidden = false;

        setManualReceiptEnabled(true);

        byId("downloadQrButton").onclick = () => {

            const link = document.createElement("a");

            link.href = data.qr_image;

            link.download =
                `netbridge-payment-${amount.toFixed(2)}.png`;

            document.body.appendChild(link);

            link.click();

            link.remove();

        };

        showMessage("qrMessage", offlineRequest
            ? "Offline request QR created on this PC. Show it to the customer; no network or app.py is needed for this face-to-face simulation."
            : "Request QR generated and saved locally. It can be used face to face without Wi-Fi. No real money was transferred.");

        showMessage(
            "merchantCodeMessage",
            "Payment request is active. Ask the customer to approve it, then type their 10-character code here."
        );

    } catch (error) {

        if (qrContainer) {
            qrContainer.hidden = true;
        }

        showMessage(
            "qrMessage",
            error.message
        );

    } finally {

        // Never keep the merchant PIN in the page after QR creation.

        pinInput.value = "";

        setButtonLoading(button, false);

    }

}


function clearReceiptPreview() {
    const codeInput = byId("manualReceiptCode");
    if (codeInput) codeInput.value = "";
    const pinInput = byId("acceptMerchantPin");
    if (pinInput) pinInput.value = "";
    const result = byId("merchantAcceptanceResult");
    if (result) result.hidden = true;
}

async function acceptCustomerReceipt() {
    const input = byId("manualReceiptCode");
    const pinInput = byId("acceptMerchantPin");
    const button = byId("acceptCustomerReceiptButton");
    const result = byId("merchantAcceptanceResult");
    if (!input || !pinInput || !result) return;
    NetBridgePaymentFeedback.unlockAudio();
    result.hidden = true;
    try {
        if (!window.netBridgeMerchantQrData) throw new Error("Generate a payment request QR first.");
        const request = JSON.parse(window.netBridgeMerchantQrData)?.data?.request;
        if (!request) throw new Error("The active merchant payment request is invalid.");
        if (Number(request.expires_at) <= Math.floor(Date.now() / 1000)) throw new Error("This payment request expired. Generate a new merchant request QR.");
        const code = input.value.trim();
        const expectedCode = await NetBridgeManualReceiptCode.generate(request, "CUSTOMER001");
        if (!NetBridgeManualReceiptCode.matches(code, expectedCode)) throw new Error("Code mismatch. Check all 10 characters and confirm the customer scanned this currently active merchant QR. If a different QR is active, use that QR for a new customer approval.");
        const pin = pinInput.value.trim();
        if (!/^\d{4}$/.test(pin)) throw new Error("Enter your four-digit merchant demo PIN.");
        const now = Math.floor(Date.now() / 1000);
        const receipt = {
            protocol: "netbridge-offline-v1", mode: "simulation_only", receipt_id: code,
            request_id: request.request_id, request_nonce: request.nonce,
            customer_user_id: "CUSTOMER001", merchant_user_id: request.merchant_user_id,
            merchant_device_id: request.merchant_device_id, amount_paise: request.amount_paise,
            currency: request.currency, approved: true, created_at: now,
            expires_at: Math.min(Number(request.expires_at), now + 300)
        };
        if (receipt.expires_at <= now) throw new Error("This payment request expired. Generate a new merchant request QR.");
        if (NetBridgeOfflineStore.receiptAlreadyUsed(receipt)) throw new Error("This request has already been recorded on this merchant device.");
        setButtonLoading(button, true, "Verifying code...");
        const pinState = await NetBridgeOfflineStore.merchantPinMatchesOrEnroll(pin);
        if (!pinState.matches) throw new Error("Incorrect local merchant demo PIN.");
        NetBridgeOfflineStore.recordIncoming(MERCHANT_ID, receipt.amount_paise, receipt);
        NetBridgePaymentFeedback.paymentReceived();
        result.className = "result-success";
        result.textContent = `Payment received (simulation): ${formatINR(receipt.amount_paise / 100)}. Code matched this active request and was recorded on this merchant device.`;
        result.hidden = false;
        showMessage("merchantCodeMessage", "Confirmation code accepted. This request is now used on this merchant device.", "success");
        input.value = "";
        pinInput.value = "";
        setManualReceiptEnabled(false);
        window.netBridgeMerchantQrData = null;
        NetBridgeOfflineStore.clearActiveRequest();
        await Promise.all([loadMerchantBalance(), loadMerchantHistory()]);
    } catch (error) {
        result.className = "result-error";
        result.textContent = error.message || "The confirmation code could not be verified.";
        result.hidden = false;
        pinInput.value = "";
        showMessage("merchantCodeMessage", error.message, "error");
    } finally {
        setButtonLoading(button, false);
        if (button && !window.netBridgeMerchantQrData) button.disabled = true;
    }
}

/* =========================================
   MERCHANT TRANSACTION HISTORY
   ========================================= */

async function loadMerchantHistory() {

    const tbody =
        byId("merchantTransactionHistory");

    const button =
        byId("refreshMerchantHistory");

    if (!tbody) return;

    if (button) {
        button.disabled = true;
    }

    const render = serverRows => {
        const transactions = NetBridgeOfflineStore.getTransactions(MERCHANT_ID, serverRows);
        tbody.replaceChildren();
        if (!transactions.length) {
            const row = tbody.insertRow();
            row.insertCell().colSpan = 3;
            row.cells[0].textContent = "No transactions recorded on this merchant device yet.";
            return;
        }
        for (const transaction of transactions.slice(0, 50)) {
            const row = tbody.insertRow();
            const isOfflineReceipt = transaction.status === "payment_received_simulation" ||
                transaction.status === "accepted_for_simulation_review" ||
                transaction.status === "pending_reconciliation";
            row.insertCell().textContent = isOfflineReceipt
                ? "Offline payment"
                : (transaction.transaction_id || transaction.id || "—");
            const amount = transaction.amount ?? (transaction.amount_paise !== undefined ? Number(transaction.amount_paise) / 100 : null);
            row.insertCell().textContent = formatINR(amount);
            let status = String(transaction.status || "Unknown");
            if (status === "payment_received_simulation" || status === "payment_received_far_simulation" || status === "accepted_for_simulation_review" || status === "pending_reconciliation") {
                status = "Payment received (simulation)";
            } else {
                status = status.replaceAll("_", " ");
            }
            row.insertCell().textContent = status;
        }
    };

    render([]);
    if (!navigator.onLine) {
        showMessage("historyMessage", "Showing history saved on this PC.");
        if (button) button.disabled = false;
        return;
    }

    let serverTransactions = [];
    try {
        const data = await apiRequest(`/api/wallets/${encodeURIComponent(MERCHANT_ID)}/transactions`);
        serverTransactions = Array.isArray(data.transactions) ? data.transactions : [];
        const farPayments = serverTransactions.filter(item => item.status === "payment_received_far_simulation");
        if (merchantFarHistoryPrimed) {
            for (const payment of farPayments) {
                const id = payment.transaction_id || payment.id;
                if (id && !merchantFarPaymentIds.has(id)) NetBridgePaymentFeedback.paymentReceived();
                if (id) merchantFarPaymentIds.add(id);
            }
        } else {
            farPayments.forEach(item => merchantFarPaymentIds.add(item.transaction_id || item.id));
            merchantFarHistoryPrimed = true;
        }
    } catch (error) {
        console.info("Using device-local merchant history:", error.message);
    }

    try {
        render(serverTransactions);
        showMessage("historyMessage", "");
    } catch (error) {
        tbody.replaceChildren();
        const row = tbody.insertRow();
        row.insertCell().colSpan = 3;
        row.cells[0].textContent = "Unable to load local transaction history.";
        showMessage("historyMessage", error.message);
    } finally {

        if (button) {
            button.disabled = false;
        }

    }

}


/* =========================================
   INITIALIZE MERCHANT DASHBOARD
   ========================================= */

document.addEventListener("DOMContentLoaded", async () => {

    await resetMerchantDemoForNewServerSession();

    byId("merchantQrForm")
        ?.addEventListener(
            "submit",
            generateMerchantQR
        );

    byId("refreshMerchantBalance")
        ?.addEventListener(
            "click",
            loadMerchantBalance
        );

    byId("refreshMerchantHistory")
        ?.addEventListener(
            "click",
            loadMerchantHistory
        );

    byId("acceptCustomerReceiptButton")
        ?.addEventListener(
            "click",
            acceptCustomerReceipt
        );


    /*
     * Initial dashboard loading.
     */

    restoreActiveMerchantRequest();
    loadMerchantBalance();

    loadMerchantHistory();

    window.setInterval(() => {
        if (navigator.onLine && document.visibilityState === "visible") {
            void Promise.all([loadMerchantBalance(), loadMerchantHistory()]);
        }
    }, 5000);
    window.addEventListener("online", () => {
        void Promise.all([loadMerchantBalance(), loadMerchantHistory()]);
    });

});



