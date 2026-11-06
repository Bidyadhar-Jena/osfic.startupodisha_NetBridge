"use strict";

(function (root) {
    // Classroom simulation only. This shared client-side key is public in the
    // app bundle, so the code is a workflow check, not payment cryptography.
    const DEMO_KEY = "NetBridge offline classroom receipt code v1";
    const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%*_-";
    const ENCODER = new TextEncoder();

    function requestMessage(request, customerId) {
        const requiredText = [request?.request_id, request?.nonce, request?.merchant_user_id,
            request?.merchant_device_id, request?.currency, customerId];
        if (requiredText.some(value => typeof value !== "string" || !value)) {
            throw new Error("The active payment request is incomplete.");
        }
        if (!Number.isSafeInteger(request.amount_paise) || request.amount_paise <= 0 ||
            !Number.isSafeInteger(request.expires_at) || request.expires_at <= 0) {
            throw new Error("The active payment request is invalid.");
        }
        // Bind the code to stable request identity and payment terms. Expiry is
        // enforced separately; excluding timestamps avoids mismatches when
        // older QR renderers serialize time fields differently.
        return ["netbridge-manual-receipt-v2", customerId, request.request_id,
            request.nonce, request.merchant_user_id, request.merchant_device_id,
            String(request.amount_paise), request.currency].join("\n");
    }

    async function generate(request, customerId = "CUSTOMER001") {
        if (!root.crypto?.subtle) throw new Error("Secure code generation is unavailable in this browser.");
        const message = requestMessage(request, customerId);
        const key = await root.crypto.subtle.importKey(
            "raw", ENCODER.encode(DEMO_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        );
        for (let counter = 0; counter < 100; counter += 1) {
            const digest = new Uint8Array(await root.crypto.subtle.sign(
                "HMAC", key, ENCODER.encode(`${message}\n${counter}`)
            ));
            let code = "";
            for (const byte of digest) {
                if (byte >= 252) continue;
                code += ALPHABET[byte % ALPHABET.length];
                if (code.length === 10) break;
            }
            if (code.length === 10 && /[A-Z]/.test(code) && /[a-z]/.test(code) && /[!@#$%*_-]/.test(code)) {
                return code;
            }
        }
        throw new Error("Could not create a mixed-character payment code. Try again.");
    }

    function matches(input, expected) {
        if (typeof input !== "string" || typeof expected !== "string" || input.length !== 10 || expected.length !== 10) {
            return false;
        }
        if (!/^[A-Za-z0-9!@#$%*_\-]{10}$/.test(input) ||
            !/[A-Z]/.test(input) || !/[a-z]/.test(input) || !/[!@#$%*_-]/.test(input)) {
            return false;
        }
        let difference = 0;
        for (let index = 0; index < 10; index += 1) difference |= input.charCodeAt(index) ^ expected.charCodeAt(index);
        return difference === 0;
    }

    root.NetBridgeManualReceiptCode = { generate, matches };
})(typeof window !== "undefined" ? window : globalThis);
