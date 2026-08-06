// ThreatVista stores every timestamp as naive UTC (datetime.utcnow() in the
// backend), so the API emits strings like "2026-08-06T10:16:00" with no offset.
// Browsers parse offset-less strings as LOCAL time, which shifts every event
// timestamp by the machine's UTC offset (e.g. 5h30m on IST devices). These
// helpers tag those strings as UTC when parsing, then render in IST
// (Asia/Kolkata) so every device shows the same correct wall-clock time.

export const IST_TIME_ZONE = 'Asia/Kolkata';

/** Parse a value the backend sent into a Date, assuming offset-less strings are UTC. */
export function toISTDate(value) {
  if (!value) return null;
  if (value instanceof Date) return new Date(value.getTime());
  const s = String(value).trim();
  if (!s) return null;
  const hasOffset = /(Z|[+-]\d{2}:?\d{2})$/i.test(s);
  const d = new Date(hasOffset ? s : `${s}Z`);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Format a backend timestamp in IST. Pass the same options you would give
 * toLocaleString() (e.g. { month: 'short', day: 'numeric', hour: '2-digit' }).
 */
export function formatIST(value, options = {}) {
  const d = toISTDate(value);
  if (!d) return '—';
  return d.toLocaleString([], { timeZone: IST_TIME_ZONE, ...options });
}

/** Render a local Date (live clock / chart axis) in IST. */
export function formatISTClock(date, options = {}) {
  if (!date) return '—';
  return date.toLocaleString([], { timeZone: IST_TIME_ZONE, ...options });
}
