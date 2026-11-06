"use strict";

(function (root) {
    let audioContext = null;

    function getAudioContext() {
        const AudioContextConstructor = root.AudioContext || root.webkitAudioContext;
        if (!AudioContextConstructor) return null;
        if (!audioContext) audioContext = new AudioContextConstructor();
        return audioContext;
    }

    function unlockAudio() {
        const context = getAudioContext();
        if (context?.state === "suspended") context.resume().catch(() => {});
    }

    function playSequence(frequencies) {
        const context = getAudioContext();
        if (!context) return;
        const play = () => {
            const oscillator = context.createOscillator();
            const volume = context.createGain();
            const start = context.currentTime + 0.015;
            oscillator.type = "sine";
            volume.gain.setValueAtTime(0.0001, start);
            frequencies.forEach((frequency, index) => {
                const noteStart = start + index * 0.18;
                oscillator.frequency.setValueAtTime(frequency, noteStart);
                volume.gain.setValueAtTime(0.0001, noteStart);
                volume.gain.linearRampToValueAtTime(0.14, noteStart + 0.018);
                volume.gain.setValueAtTime(0.14, noteStart + 0.105);
                volume.gain.exponentialRampToValueAtTime(0.0001, noteStart + 0.145);
            });
            oscillator.connect(volume);
            volume.connect(context.destination);
            oscillator.start(start);
            oscillator.stop(start + frequencies.length * 0.18);
        };
        if (context.state === "suspended") context.resume().then(play).catch(() => {});
        else play();
    }

    function qrDetected() {
        if (root.navigator?.vibrate) {
            try { root.navigator.vibrate([300, 100, 300, 100, 500]); } catch (_) {}
        }
    }

    root.NetBridgePaymentFeedback = {
        unlockAudio,
        qrDetected,
        paymentSent: () => playSequence([660, 880]),
        paymentReceived: () => playSequence([660, 880, 1046])
    };
})(typeof window !== "undefined" ? window : globalThis);
