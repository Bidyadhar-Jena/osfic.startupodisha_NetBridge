"use strict";

(function (root) {
    const VERSION = 1;
    const CUSTOMER_ID = "CUSTOMER001";
    const RECEIVER_ID = "CUSTOMER002";
    const MERCHANT_ID = "MERCHANT001";
    const DEFAULTS = { [CUSTOMER_ID]: 50000, [RECEIVER_ID]: 50000, [MERCHANT_ID]: 10000 };

    function storageKey(userId) {
        return `netbridge.offline.wallet.${userId}.v${VERSION}`;
    }

    function newState(userId, seedBalancePaise) {
        const balance = Number.isSafeInteger(seedBalancePaise) && seedBalancePaise >= 0
            ? seedBalancePaise
            : (DEFAULTS[userId] || 0);
        return {
            server_balance_paise: balance,
            pending_delta_paise: 0,
            balance_paise: balance,
            transactions: [],
            pending_far_payments: [],
            used_receipt_ids: [],
            used_request_ids: [],
            active_request: null,
            merchant_pin: null
        };
    }

    function read(userId, seedBalancePaise) {
        let state;
        try {
            state = JSON.parse(root.localStorage.getItem(storageKey(userId)) || "null");
        } catch (_) {
            state = null;
        }
        if (!state || typeof state !== "object") state = newState(userId, seedBalancePaise);
        if (!Array.isArray(state.transactions)) state.transactions = [];
        if (!Array.isArray(state.pending_far_payments)) state.pending_far_payments = [];
        if (!Array.isArray(state.used_receipt_ids)) state.used_receipt_ids = [];
        if (!Array.isArray(state.used_request_ids)) state.used_request_ids = [];
        if (!Number.isSafeInteger(state.server_balance_paise)) {
            state.server_balance_paise = Number.isSafeInteger(seedBalancePaise)
                ? seedBalancePaise
                : (DEFAULTS[userId] || 0);
        }
        if (!Number.isSafeInteger(state.pending_delta_paise)) state.pending_delta_paise = 0;
        state.balance_paise = state.server_balance_paise + state.pending_delta_paise;
        return state;
    }

    function write(userId, state) {
        state.balance_paise = state.server_balance_paise + state.pending_delta_paise;
        if (state.balance_paise < 0) throw new Error("The local demo wallet has insufficient balance.");
        root.localStorage.setItem(storageKey(userId), JSON.stringify(state));
        return state;
    }

    function seedFromServer(userId, balancePaise) {
        if (!Number.isSafeInteger(balancePaise) || balancePaise < 0) {
            throw new Error("The server returned an invalid wallet balance.");
        }
        const state = read(userId, balancePaise);
        state.server_balance_paise = balancePaise;
        return write(userId, state);
    }

    function resetDemoState(userId) {
        const defaults = { [CUSTOMER_ID]: 50000, [RECEIVER_ID]: 50000, [MERCHANT_ID]: 10000 };
        const previous = read(userId);
        const fresh = newState(userId, defaults[userId] || 0);
        // Keep the merchant's local PIN enrollment across a server restart.
        if (userId === MERCHANT_ID) fresh.merchant_pin = previous.merchant_pin;
        if (userId === CUSTOMER_ID && previous.pending_far_payments.length) {
            // Pending remote payments are instructions awaiting delivery, not
            // completed history. Preserve their local balance reservations.
            fresh.pending_far_payments = previous.pending_far_payments;
            fresh.pending_delta_paise = -previous.pending_far_payments.reduce(
                (total, item) => total + item.amount_paise, 0
            );
            const pendingIds = new Set(previous.pending_far_payments.map(item => item.transaction_id));
            fresh.transactions = previous.transactions.filter(item => pendingIds.has(item.transaction_id));
        }
        return write(userId, fresh);
    }

    function getBalance(userId) {
        const state = read(userId);
        write(userId, state);
        return state.balance_paise;
    }

    function getPendingDelta(userId) {
        return read(userId).pending_delta_paise;
    }

    function getPendingFarPayments(userId) {
        return read(userId).pending_far_payments.slice();
    }

    function queueFarPayment(userId, payment) {
        if (!payment || typeof payment.transaction_id !== "string" ||
            typeof payment.recipient_upi_id !== "string" ||
            !Number.isSafeInteger(payment.amount_paise) || payment.amount_paise <= 0) {
            throw new Error("Far payment details are invalid.");
        }
        const state = read(userId);
        if (state.pending_far_payments.some(item => item.transaction_id === payment.transaction_id) ||
            state.transactions.some(item => item.transaction_id === payment.transaction_id)) {
            throw new Error("This far payment is already saved on this phone.");
        }
        if (state.balance_paise < payment.amount_paise) {
            throw new Error("The local demo wallet has insufficient balance.");
        }
        const queued = {
            transaction_id: payment.transaction_id,
            recipient_upi_id: payment.recipient_upi_id,
            amount_paise: payment.amount_paise,
            created_at: payment.created_at || Math.floor(Date.now() / 1000)
        };
        state.pending_delta_paise -= queued.amount_paise;
        state.pending_far_payments.push(queued);
        state.transactions.unshift({
            transaction_id: queued.transaction_id,
            amount_paise: queued.amount_paise,
            status: "payment_queued_offline",
            created_at: queued.created_at,
            recipient_upi_id: queued.recipient_upi_id,
            local_offline: true
        });
        return write(userId, state);
    }

    function completeFarPayment(userId, transactionId, senderBalancePaise) {
        if (!Number.isSafeInteger(senderBalancePaise) || senderBalancePaise < 0) {
            throw new Error("The server returned an invalid wallet balance.");
        }
        const state = read(userId, senderBalancePaise);
        const index = state.pending_far_payments.findIndex(item => item.transaction_id === transactionId);
        state.server_balance_paise = senderBalancePaise;
        if (index !== -1) {
            const [completed] = state.pending_far_payments.splice(index, 1);
            state.pending_delta_paise += completed.amount_paise;
            const transaction = state.transactions.find(item => item.transaction_id === transactionId);
            if (transaction) {
                transaction.status = "payment_sent_far_simulation";
                transaction.local_offline = false;
            }
        }
        return write(userId, state);
    }

    function getTransactions(userId, serverTransactions = []) {
        const state = read(userId);
        const seen = new Set(state.transactions.map(item => item.transaction_id));
        const combined = [
            ...state.transactions,
            ...(Array.isArray(serverTransactions)
                ? serverTransactions.filter(item => !seen.has(item.transaction_id || item.id))
                : [])
        ];
        return combined.sort((left, right) =>
            Number(right.created_at || 0) - Number(left.created_at || 0)
        );
    }

    function recordOutgoing(userId, amountPaise, receipt) {
        if (!Number.isSafeInteger(amountPaise) || amountPaise <= 0) {
            throw new Error("The payment amount is invalid.");
        }
        const state = read(userId);
        if (state.used_request_ids.includes(receipt.request_id)) {
            throw new Error("This merchant request has already been used on this phone.");
        }
        if (state.balance_paise < amountPaise) throw new Error("The local demo wallet has insufficient balance.");
        state.used_request_ids.unshift(receipt.request_id);
        state.used_request_ids = state.used_request_ids.slice(0, 500);
        state.pending_delta_paise -= amountPaise;
        state.transactions.unshift({
            transaction_id: `offline-${receipt.request_id || Date.now()}`,
            amount_paise: amountPaise,
            status: "payment_sent_simulation",
            created_at: receipt.created_at,
            local_offline: true
        });
        return write(userId, state);
    }

    function receiptAlreadyUsed(receipt) {
        const state = read(MERCHANT_ID);
        const receiptId = typeof receipt === "string" ? receipt : receipt?.receipt_id;
        const requestId = typeof receipt === "object" ? receipt?.request_id : null;
        return state.used_receipt_ids.includes(receiptId) ||
            (requestId !== null && state.used_request_ids.includes(requestId));
    }

    function recordIncoming(userId, amountPaise, receipt) {
        if (!Number.isSafeInteger(amountPaise) || amountPaise <= 0) {
            throw new Error("The payment amount is invalid.");
        }
        const state = read(userId);
        if (state.used_receipt_ids.includes(receipt.receipt_id) || state.used_request_ids.includes(receipt.request_id)) {
            throw new Error("This receipt or merchant request has already been used on this device.");
        }
        state.used_receipt_ids.unshift(receipt.receipt_id);
        state.used_receipt_ids = state.used_receipt_ids.slice(0, 500);
        state.used_request_ids.unshift(receipt.request_id);
        state.used_request_ids = state.used_request_ids.slice(0, 500);
        state.pending_delta_paise += amountPaise;
        state.transactions.unshift({
            transaction_id: `offline-${receipt.request_id || Date.now()}`,
            amount_paise: amountPaise,
            status: "payment_received_simulation",
            created_at: receipt.created_at,
            local_offline: true
        });
        return write(userId, state);
    }

    function getActiveRequest() {
        return read(MERCHANT_ID).active_request;
    }

    function setActiveRequest(rawQr) {
        const state = read(MERCHANT_ID);
        state.active_request = rawQr;
        write(MERCHANT_ID, state);
    }

    function clearActiveRequest() {
        const state = read(MERCHANT_ID);
        state.active_request = null;
        write(MERCHANT_ID, state);
    }

    function bytesToBase64(bytes) {
        let binary = "";
        for (const byte of bytes) binary += String.fromCharCode(byte);
        return root.btoa(binary);
    }

    async function merchantPinMatchesOrEnroll(pin, replaceExisting = false) {
        if (!/^\d{4}$/.test(pin)) throw new Error("Enter your four-digit merchant demo PIN.");
        if (!root.crypto?.subtle) throw new Error("Secure local storage is unavailable in this browser.");
        const state = read(MERCHANT_ID);
        const encoder = new TextEncoder();
        let record = state.merchant_pin;
        if (!record || replaceExisting) {
            record = {
                salt: bytesToBase64(root.crypto.getRandomValues(new Uint8Array(16))),
                hash: ""
            };
            const material = await root.crypto.subtle.importKey("raw", encoder.encode(pin), "PBKDF2", false, ["deriveBits"]);
            const derived = await root.crypto.subtle.deriveBits(
                { name: "PBKDF2", salt: Uint8Array.from(root.atob(record.salt), c => c.charCodeAt(0)), iterations: 120000, hash: "SHA-256" },
                material,
                256
            );
            record.hash = bytesToBase64(new Uint8Array(derived));
            state.merchant_pin = record;
            write(MERCHANT_ID, state);
            return { matches: true, enrolled: true };
        }
        const material = await root.crypto.subtle.importKey("raw", encoder.encode(pin), "PBKDF2", false, ["deriveBits"]);
        const derived = await root.crypto.subtle.deriveBits(
            { name: "PBKDF2", salt: Uint8Array.from(root.atob(record.salt), c => c.charCodeAt(0)), iterations: 120000, hash: "SHA-256" },
            material,
            256
        );
        const candidate = bytesToBase64(new Uint8Array(derived));
        let difference = candidate.length ^ record.hash.length;
        for (let i = 0; i < Math.max(candidate.length, record.hash.length); i += 1) {
            difference |= (candidate.charCodeAt(i) || 0) ^ (record.hash.charCodeAt(i) || 0);
        }
        return { matches: difference === 0, enrolled: false };
    }

    root.NetBridgeOfflineStore = {
        seedFromServer,
        resetDemoState,
        getBalance,
        getPendingDelta,
        getPendingFarPayments,
        queueFarPayment,
        completeFarPayment,
        getTransactions,
        recordOutgoing,
        recordIncoming,
        receiptAlreadyUsed,
        getActiveRequest,
        setActiveRequest,
        clearActiveRequest,
        merchantPinMatchesOrEnroll
    };
})(typeof window !== "undefined" ? window : globalThis);
