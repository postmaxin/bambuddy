import { describe, it, expect } from 'vitest';
import { getUnmetPasswordRules, isPasswordValid } from '../../utils/password';

describe('getUnmetPasswordRules', () => {
  it('returns every rule for an empty password', () => {
    expect(getUnmetPasswordRules('')).toEqual([
      'tooShort',
      'needsUppercase',
      'needsLowercase',
      'needsDigit',
      'needsSpecial',
    ]);
  });

  it('returns all unmet rules at once, not just the first', () => {
    // The #1303 / fork #9 case: 8 digits fails uppercase, lowercase and special together.
    expect(getUnmetPasswordRules('12345678')).toEqual(['needsUppercase', 'needsLowercase', 'needsSpecial']);
    expect(getUnmetPasswordRules('abcdefgh')).toEqual(['needsUppercase', 'needsDigit', 'needsSpecial']);
  });

  it('flags only length when everything else is met', () => {
    expect(getUnmetPasswordRules('Ab1!def')).toEqual(['tooShort']);
  });

  it('flags a single missing class', () => {
    expect(getUnmetPasswordRules('ABCDEFG1!')).toEqual(['needsLowercase']);
    expect(getUnmetPasswordRules('Abcdefg1')).toEqual(['needsSpecial']);
    expect(getUnmetPasswordRules('Abcdefg!')).toEqual(['needsDigit']);
  });

  it('returns an empty list for a password that meets every rule', () => {
    expect(getUnmetPasswordRules('Aa1!aaaa')).toEqual([]);
    expect(getUnmetPasswordRules('Aa1!Aa1!Aa1!')).toEqual([]);
  });
});

describe('isPasswordValid', () => {
  it('is true only when no rule is unmet', () => {
    expect(isPasswordValid('Aa1!aaaa')).toBe(true);
    expect(isPasswordValid('Aa1!aaa')).toBe(false);
    expect(isPasswordValid('')).toBe(false);
  });
});
