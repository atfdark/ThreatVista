/**
 * Browser-Native Web Audio API Synthesizer for ThreatVista SOC Alerts.
 *
 * Generates futuristic dual-tone attention chimes without any external mp3/asset
 * dependencies. Handles browser autoplay restrictions gracefully by lazily
 * instantiating and auto-resuming AudioContext on user gestures.
 *
 * Supports continuous repetitive beeping until an alert is Acknowledged by the SOC analyst.
 */

let audioCtx = null;
const SOUND_STORAGE_KEY = 'threatvista_sound_enabled';

// Initialize audio enabled preference from localStorage (default: true)
function getSoundPreference() {
  const saved = localStorage.getItem(SOUND_STORAGE_KEY);
  return saved === null ? true : saved === 'true';
}

let soundEnabled = getSoundPreference();
let beepIntervalId = null;

function getAudioContext() {
  if (!audioCtx) {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (AudioContextClass) {
      audioCtx = new AudioContextClass();
    }
  }
  if (audioCtx && audioCtx.state === 'suspended') {
    audioCtx.resume().catch(() => {});
  }
  return audioCtx;
}

// Auto-unlock AudioContext on first user interaction anywhere on the window
if (typeof window !== 'undefined') {
  const unlockAudio = () => {
    const ctx = getAudioContext();
    if (ctx && ctx.state === 'running') {
      window.removeEventListener('click', unlockAudio);
      window.removeEventListener('keydown', unlockAudio);
      window.removeEventListener('touchstart', unlockAudio);
    }
  };
  window.addEventListener('click', unlockAudio, { passive: true });
  window.addEventListener('keydown', unlockAudio, { passive: true });
  window.addEventListener('touchstart', unlockAudio, { passive: true });
}

/**
 * Play prominent dual-tone security alert chime (880 Hz -> 1760 Hz pulsing alarm).
 */
export function playSecurityAlertSound() {
  if (!soundEnabled) return false;

  try {
    const ctx = getAudioContext();
    if (!ctx) return false;

    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }

    const now = ctx.currentTime;

    // Pulse 1: Attention High-Tone (880 Hz - A5)
    const osc1 = ctx.createOscillator();
    const gain1 = ctx.createGain();
    osc1.type = 'sine';
    osc1.frequency.setValueAtTime(880, now);
    osc1.frequency.exponentialRampToValueAtTime(1320, now + 0.12);

    gain1.gain.setValueAtTime(0.001, now);
    gain1.gain.linearRampToValueAtTime(0.35, now + 0.02);
    gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.25);

    osc1.connect(gain1);
    gain1.connect(ctx.destination);

    osc1.start(now);
    osc1.stop(now + 0.26);

    // Pulse 2: Urgent Harmonic Pulse (1760 Hz - A6)
    const osc2 = ctx.createOscillator();
    const gain2 = ctx.createGain();
    osc2.type = 'triangle';
    osc2.frequency.setValueAtTime(1320, now + 0.15);
    osc2.frequency.exponentialRampToValueAtTime(1760, now + 0.35);

    gain2.gain.setValueAtTime(0.001, now + 0.15);
    gain2.gain.linearRampToTime(0.4, now + 0.18);
    gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.55);

    osc2.connect(gain2);
    gain2.connect(ctx.destination);

    osc2.start(now + 0.15);
    osc2.stop(now + 0.56);

    return true;
  } catch (e) {
    // Fallback: simpler tone in case of older AudioContext
    try {
      const ctx = getAudioContext();
      if (!ctx) return false;
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'square';
      osc.frequency.setValueAtTime(987.77, now); // B5
      gain.gain.setValueAtTime(0.2, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.35);
      return true;
    } catch (err2) {
      console.warn('[Sound] Audio playback failed:', err2);
      return false;
    }
  }
}

/**
 * Start repeating alert beeps until stopped (loops every 1.6s).
 */
export function startAlertBeepLoop() {
  if (beepIntervalId !== null) return; // Already beeping

  // Play immediately on trigger
  if (soundEnabled) {
    playSecurityAlertSound();
  }

  // Schedule continuous alarm repeat every 1.6 seconds
  beepIntervalId = setInterval(() => {
    if (soundEnabled) {
      playSecurityAlertSound();
    }
  }, 1600);
}

/**
 * Stop the repeating alert beeps immediately when Ack / Resolve is clicked.
 */
export function stopAlertBeepLoop() {
  if (beepIntervalId !== null) {
    clearInterval(beepIntervalId);
    beepIntervalId = null;
  }
}

/**
 * Check if the alert alarm is currently looping.
 */
export function isAlertBeeping() {
  return beepIntervalId !== null;
}

/**
 * Play soft acknowledgment / resolution confirmation chirp (523 Hz -> 1046 Hz).
 */
export function playAcknowledgeSound() {
  if (!soundEnabled) return false;

  try {
    const ctx = getAudioContext();
    if (!ctx) return false;

    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }

    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.setValueAtTime(523.25, now); // C5
    osc.frequency.exponentialRampToValueAtTime(1046.5, now + 0.15); // C6

    gain.gain.setValueAtTime(0.001, now);
    gain.gain.linearRampToValueAtTime(0.2, now + 0.03);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start(now);
    osc.stop(now + 0.31);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Check if sound notifications are enabled.
 */
export function isSoundEnabled() {
  return soundEnabled;
}

/**
 * Toggle sound enabled state.
 */
export function setSoundEnabled(enabled) {
  soundEnabled = Boolean(enabled);
  localStorage.setItem(SOUND_STORAGE_KEY, String(soundEnabled));
  if (!soundEnabled) {
    stopAlertBeepLoop();
  } else {
    // Play a gentle chirp to verify sound is active
    playAcknowledgeSound();
  }
  return soundEnabled;
}

/**
 * Manual test alert sound for SOC administrators.
 */
export function testAlertSound() {
  const ctx = getAudioContext();
  if (ctx && ctx.state === 'suspended') {
    ctx.resume();
  }
  return playSecurityAlertSound();
}
