(function (root, factory) {
    const api = factory();
    if (typeof module === "object" && module.exports) {
        module.exports = api;
    } else {
        root.NetBridgeOfflineTOTP = api;
    }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
    "use strict";

    const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const PBKDF2_ITERATIONS = 250000;
    const encoder = new TextEncoder();

    function base32ToBytes(secret) {
        if (typeof secret !== "string" || !secret.trim()) {
            throw new Error("Authenticator secret is missing.");
        }
        let bits = 0;
        let value = 0;
        const bytes = [];
        const normalized = secret.replace(/=+$/g, "").replace(/\s/g, "").toUpperCase();
        for (const character of normalized) {
            const digit = BASE32.indexOf(character);
            if (digit < 0) throw new Error("Authenticator secret is invalid.");
            value = (value << 5) | digit;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                bytes.push((value >>> bits) & 255);
                value &= (1 << bits) - 1;
            }
        }
        if (bytes.length < 16) throw new Error("Authenticator secret is too short.");
        return new Uint8Array(bytes);
    }

    function bytesToBase32(bytes) {
        let output = "";
        let value = 0;
        let bits = 0;
        for (const byte of bytes) {
            value = (value << 8) | byte;
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                output += BASE32[(value >>> bits) & 31];
            }
            value &= (1 << bits) - 1;
        }
        if (bits) output += BASE32[(value << (5 - bits)) & 31];
        return output;
    }

    function generateSecret() {
        if (!globalThis.crypto?.getRandomValues) {
            throw new Error("Secure random generation is unavailable in this browser.");
        }
        return bytesToBase32(globalThis.crypto.getRandomValues(new Uint8Array(20)));
    }

    function toBase64(bytes) {
        let binary = "";
        for (const byte of bytes) binary += String.fromCharCode(byte);
        return btoa(binary);
    }

    function fromBase64(value) {
        const binary = atob(value);
        return Uint8Array.from(binary, character => character.charCodeAt(0));
    }

    async function codeForCounter(secret, counter) {
        if (!Number.isSafeInteger(counter) || counter < 0) {
            throw new Error("Invalid Authenticator time step.");
        }
        const cryptoApi = globalThis.crypto;
        if (!cryptoApi?.subtle) throw new Error("Secure browser cryptography is unavailable.");
        const key = await cryptoApi.subtle.importKey(
            "raw",
            base32ToBytes(secret),
            { name: "HMAC", hash: "SHA-1" },
            false,
            ["sign"]
        );
        let value = BigInt(counter);
        const message = new Uint8Array(8);
        for (let index = 7; index >= 0; index -= 1) {
            message[index] = Number(value & 255n);
            value >>= 8n;
        }
        const digest = new Uint8Array(await cryptoApi.subtle.sign("HMAC", key, message));
        const offset = digest[digest.length - 1] & 15;
        const binary = ((digest[offset] & 127) * 0x1000000) +
            (digest[offset + 1] << 16) +
            (digest[offset + 2] << 8) +
            digest[offset + 3];
        return String(binary % 1000000).padStart(6, "0");
    }

    async function verifyCode(secret, otp, nowMs = Date.now(), window = 1, lastUsedCounter = -1) {
        if (typeof otp !== "string" || !/^\d{6}$/.test(otp) || !Number.isFinite(nowMs)) return null;
        if (!Number.isInteger(window) || window < 0 || window > 2) throw new Error("Invalid OTP time window.");
        const currentCounter = Math.floor(nowMs / 30000);
        for (let offset = -window; offset <= window; offset += 1) {
            const counter = currentCounter + offset;
            if (counter <= lastUsedCounter || counter < 0) continue;
            if (await codeForCounter(secret, counter) === otp) return counter;
        }
        return null;
    }

    async function deriveEncryptionKey(pin, salt) {
        if (typeof pin !== "string" || !/^\d{4}$/.test(pin)) {
            throw new Error("Enter your 4-digit customer PIN.");
        }
        const cryptoApi = globalThis.crypto;
        const material = await cryptoApi.subtle.importKey(
            "raw", encoder.encode(pin), "PBKDF2", false, ["deriveKey"]
        );
        return cryptoApi.subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
            material,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async function saveCredential(userId, pin, secret, lastUsedCounter = -1) {
        if (!globalThis.crypto?.subtle || !globalThis.localStorage) {
            throw new Error("This browser cannot save offline Authenticator data.");
        }
        if (!Number.isSafeInteger(lastUsedCounter) || lastUsedCounter < -1) {
            throw new Error("Invalid Authenticator replay state.");
        }
        base32ToBytes(secret);
        const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
        const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveEncryptionKey(pin, salt);
        const plain = encoder.encode(JSON.stringify({ secret, lastUsedCounter }));
        const encrypted = await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);
        localStorage.setItem(`netbridge.offline.totp.${userId}.v1`, JSON.stringify({
            salt: toBase64(salt),
            iv: toBase64(iv),
            encrypted: toBase64(new Uint8Array(encrypted))
        }));
    }

    async function loadCredential(userId, pin) {
        const recordText = globalThis.localStorage?.getItem(`netbridge.offline.totp.${userId}.v1`);
        if (!recordText) return null;
        try {
            const record = JSON.parse(recordText);
            const salt = fromBase64(record.salt);
            const iv = fromBase64(record.iv);
            const encrypted = fromBase64(record.encrypted);
            const key = await deriveEncryptionKey(pin, salt);
            const plain = await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
            const credential = JSON.parse(new TextDecoder().decode(plain));
            base32ToBytes(credential.secret);
            if (!Number.isSafeInteger(credential.lastUsedCounter) || credential.lastUsedCounter < -1) {
                throw new Error("Invalid Authenticator replay state.");
            }
            return credential;
        } catch (_) {
            throw new Error("Customer PIN does not unlock the cached Authenticator setup.");
        }
    }

    async function verifyAndConsume(userId, pin, otp, nowMs = Date.now()) {
        const credential = await loadCredential(userId, pin);
        if (!credential) throw new Error("Connect Authenticator online once to prepare offline verification.");
        const counter = await verifyCode(credential.secret, otp, nowMs, 1, credential.lastUsedCounter);
        if (counter === null) return false;
        await saveCredential(userId, pin, credential.secret, counter);
        return true;
    }

    return { codeForCounter, verifyCode, saveCredential, loadCredential, verifyAndConsume, generateSecret };
});
