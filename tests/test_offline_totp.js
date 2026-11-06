const assert = require("node:assert/strict");
const TOTP = require(".../static/offline_totp.js");

class MemoryStorage {
    constructor() { this.values = new Map(); }
    getItem(key) { return this.values.get(key) ?? null; }
    setItem(key, value) { this.values.set(key, String(value)); }
}

globalThis.localStorage = new MemoryStorage();

(async () => {
    const userId = "CUSTOMER001";
    const pin = "1234";
    const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    const now = 1700000000000;
    const counter = Math.floor(now / 30000);
    const correct = await TOTP.codeForCounter(secret, counter);
    const wrong = String((Number(correct) + 1) % 1000000).padStart(6, "0");

    assert.equal(await TOTP.verifyCode(secret, correct, now, 1, counter - 1), counter);
    assert.equal(await TOTP.verifyCode(secret, wrong, now, 1, counter - 1), null);
    await TOTP.saveCredential(userId, pin, secret, counter - 1);
    assert.equal((await TOTP.loadCredential(userId, pin)).secret, secret);
    await assert.rejects(() => TOTP.loadCredential(userId, "9999"));
    assert.equal(await TOTP.verifyAndConsume(userId, pin, wrong, now), false);
    assert.equal(await TOTP.verifyAndConsume(userId, pin, correct, now), true);
    assert.equal(await TOTP.verifyAndConsume(userId, pin, correct, now), false);
    const credential = await TOTP.loadCredential(userId, pin);
    assert.equal(await TOTP.verifyCode(secret, correct, now, 1, credential.lastUsedCounter), null,
        "a consumed OTP must not authorize another payment");
    assert.equal(await TOTP.verifyCode(secret, correct, now, 1, -1), counter,
        "a valid current OTP may reconnect without consuming payment authorization");
    console.log("Offline TOTP test passed: rejects wrong OTP and replay, accepts current OTP with correct PIN.");
})().catch(error => {
    console.error(error);
    process.exit(1);
});
