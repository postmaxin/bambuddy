/**
 * Password rules matching the backend in
 * `backend/app/schemas/auth.py` (`unmet_password_rules`): length >= 8, an
 * uppercase letter, a lowercase letter, a digit and a special character.
 *
 * The UI shows every rule up front and ticks each one live, so the helper
 * returns ALL unmet rules (in display order), not just the first. The server
 * stays the authority; this only drives the checklist and the submit gate.
 */
export type PasswordRequirementKey =
  | 'tooShort'
  | 'needsUppercase'
  | 'needsLowercase'
  | 'needsDigit'
  | 'needsSpecial';

export const PASSWORD_MIN_LENGTH = 8;

/** Display order; each rule's i18n label lives at `passwordRules.<labelKey>`. */
export const PASSWORD_RULES: ReadonlyArray<{
  key: PasswordRequirementKey;
  labelKey: 'minLength' | 'uppercase' | 'lowercase' | 'digit' | 'special';
  test: (password: string) => boolean;
}> = [
  { key: 'tooShort', labelKey: 'minLength', test: (p) => p.length >= PASSWORD_MIN_LENGTH },
  { key: 'needsUppercase', labelKey: 'uppercase', test: (p) => /[A-Z]/.test(p) },
  { key: 'needsLowercase', labelKey: 'lowercase', test: (p) => /[a-z]/.test(p) },
  { key: 'needsDigit', labelKey: 'digit', test: (p) => /\d/.test(p) },
  { key: 'needsSpecial', labelKey: 'special', test: (p) => /[^A-Za-z0-9]/.test(p) },
];

export function getUnmetPasswordRules(password: string): PasswordRequirementKey[] {
  return PASSWORD_RULES.filter((rule) => !rule.test(password)).map((rule) => rule.key);
}

export function isPasswordValid(password: string): boolean {
  return getUnmetPasswordRules(password).length === 0;
}
