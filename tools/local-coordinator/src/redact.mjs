// Secret masking applied to every string that leaves the service (browser API, logs).
// Conservative: masks values that follow secret-like keywords, well-known token
// shapes, mnemonic phrases after a seed/mnemonic keyword, the anvil development
// mnemonic, and every runtime token registered by this service.

export const MASK = '[محجوب]';
const KEY = '(?:priv(?:ate)?[_ -]?key|privkey|secret|seed|password|passphrase|api[_-]?key|access[_-]?token|token|bearer|authorization|"priv")';

// [regex, keepPrefix]: when keepPrefix is true, group 1 is kept and group 2 is masked.
const RULES = [
  [new RegExp(`((?:mnemonic|seed phrase|recovery phrase)["']?\\s*[:=]?\\s*["']?)((?:[a-z]{3,8} ){11,23}[a-z]{3,8})`, 'gi'), true],
  [new RegExp(`(${KEY}["']?\\s*[:=]\\s*["']?)([^\\s"',}]{8,200})`, 'gi'), true],
  [new RegExp(`(${KEY}[^\\n]{0,40}?)((?:0x)?[0-9a-fA-F]{64})`, 'gi'), true],
  [/(?:sk-(?:ant-)?[A-Za-z0-9_-]{16,})/g, false],
  [/(?:gh[pousr]_[A-Za-z0-9]{20,})/g, false],
  [/(?:github_pat_[A-Za-z0-9_]{20,})/g, false],
  [/(?:AKIA[0-9A-Z]{16})/g, false],
  [/(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g, false],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, false],
  [/test test test test test test test test test test test junk/g, false],
];

const runtimeSecrets = new Set();
export function registerSecret(value) { if (typeof value === 'string' && value.length >= 16) runtimeSecrets.add(value); }

export function redact(text) {
  if (typeof text !== 'string' || !text) return text;
  let out = text;
  for (const s of runtimeSecrets) out = out.split(s).join(MASK);
  for (const [re, keepPrefix] of RULES) {
    out = out.replace(re, (whole, g1) => (keepPrefix ? g1 + MASK : MASK));
  }
  return out;
}

/** Recursively redact every string (keys included) in a JSON-like value. */
export function redactDeep(v) {
  if (typeof v === 'string') return redact(v);
  if (Array.isArray(v)) return v.map(redactDeep);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [redact(k), redactDeep(x)]));
  return v;
}
