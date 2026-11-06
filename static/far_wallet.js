"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const page = document.getElementById("receiverWallet");
    const walletId = page?.dataset.walletId;
    const balance = document.getElementById("receiverBalance");
    const status = document.getElementById("receiverStatus");
    const history = document.getElementById("receiverHistory");
    const refresh = document.getElementById("receiverRefresh");
    if (!walletId || !balance || !status || !history) return;

    const formatINR = value => new Intl.NumberFormat("en-IN", {
        style: "currency", currency: "INR", minimumFractionDigits: 2
    }).format(Number(value));

    async function updateReceiverWallet() {
        if (!navigator.onLine) {
            status.textContent = "Offline. This wallet will show new payments when it reconnects to NetBridge.";
            status.dataset.state = "info";
            return;
        }
        try {
            const [balanceResponse, historyResponse] = await Promise.all([
                fetch(`/api/wallets/${encodeURIComponent(walletId)}/balance`, { cache: "no-store" }),
                fetch(`/api/wallets/${encodeURIComponent(walletId)}/transactions`, { cache: "no-store" })
            ]);
            const balanceData = await balanceResponse.json();
            const historyData = await historyResponse.json();
            if (!balanceResponse.ok || !historyResponse.ok) {
                throw new Error(balanceData.error || historyData.error || "Could not load receiver wallet.");
            }
            balance.textContent = formatINR(balanceData.balance_rupees);
            const payments = Array.isArray(historyData.transactions) ? historyData.transactions : [];
            history.replaceChildren();
            if (!payments.length) {
                const empty = document.createElement("li");
                empty.textContent = "No payments received yet.";
                history.appendChild(empty);
            } else {
                for (const payment of payments.slice(0, 20)) {
                    const row = document.createElement("li");
                    const amount = payment.amount ?? (Number(payment.amount_paise) / 100);
                    const received = payment.status === "payment_received_far_simulation";
                    row.textContent = `${received ? "Payment received (simulation)" : String(payment.status || "Activity").replaceAll("_", " ")} · ${formatINR(amount)}`;
                    history.appendChild(row);
                }
            }
            status.textContent = "Connected. New payments appear automatically after they are delivered.";
            status.dataset.state = "success";
        } catch (error) {
            status.textContent = `${error.message} New payments are not confirmed until they appear here.`;
            status.dataset.state = "error";
        }
    }

    refresh?.addEventListener("click", updateReceiverWallet);
    window.addEventListener("online", updateReceiverWallet);
    window.setInterval(() => {
        if (document.visibilityState === "visible") void updateReceiverWallet();
    }, 5000);
    void updateReceiverWallet();
});
