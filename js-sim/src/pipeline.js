// Pipeline to wire RE-grounded function aliases to behaviors
// For now, all behaviors are placeholders; replace with exact logic as decomp proceeds
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const findingsPath = path.join(root, 'findings.json');

export function loadFindings() {
  if (!fs.existsSync(findingsPath)) {
    return {};
  }
  return JSON.parse(fs.readFileSync(findingsPath, 'utf-8'));
}

// Map from alias to JS function implementing discovered behavior (placeholder now)
export const physImpl = new Map();

// Example registration stubs — these do nothing yet until formulas are confirmed
export function registerPlaceholder(alias) {
  if (!physImpl.has(alias)) {
    physImpl.set(alias, (state, args) => state);
  }
}

export function bootstrapFromFindings() {
  const f = loadFindings();
  Object.values(f).forEach(list => {
    list.forEach(entry => registerPlaceholder(entry.alias));
  });
  return physImpl.size;
}
