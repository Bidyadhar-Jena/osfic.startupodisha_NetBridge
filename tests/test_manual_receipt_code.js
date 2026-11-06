const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
if (!globalThis.crypto?.subtle) globalThis.crypto = webcrypto;
require(".../static/offline_receipt_code.js");
const Code = globalThis.NetBridgeManualReceiptCode;
const request = {
  request_id: "request-123", nonce: "nonce-456", merchant_user_id: "MERCHANT001",
  merchant_device_id: "MERCHANT-OFFLINE-device", amount_paise: 12345, currency: "INR",
  created_at: 1793900000, expires_at: 1793900300
};
(async () => {
  const code = await Code.generate(request);
  assert.equal(code.length, 10);
  assert.match(code, /[A-Z]/);
  assert.match(code, /[a-z]/);
  assert.match(code, /[!@#$%*_-]/);
  assert.equal(Code.matches(code, code), true);
  assert.equal(Code.matches(`${code.slice(0, 9)}?`, code), false);
  assert.equal(Code.matches(code.toLowerCase(), code), false);
  const changedRequest = { ...request, amount_paise: 12346 };
  assert.notEqual(await Code.generate(changedRequest), code);
  console.log("Manual receipt code test passed: mixed 10-character code, request binding, and invalid-code rejection.");
})().catch(error => { console.error(error); process.exitCode = 1; });
