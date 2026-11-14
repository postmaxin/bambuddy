import { describe, it, expect } from 'vitest';
import { screen } from '@testing-library/react';
import { render } from '../utils';
import { PasswordRules } from '../../components/PasswordRules';

const met = (key: string) => screen.getByTestId(`password-rule-${key}`).getAttribute('data-met');

describe('PasswordRules', () => {
  it('lists every rule before anything is typed, all unmet', () => {
    render(<PasswordRules password="" />);
    for (const key of ['tooShort', 'needsUppercase', 'needsLowercase', 'needsDigit', 'needsSpecial']) {
      expect(met(key)).toBe('false');
    }
    expect(screen.getAllByRole('listitem')).toHaveLength(5);
  });

  it('ticks each rule as the password meets it', () => {
    render(<PasswordRules password="abcdefgh" />);
    expect(met('tooShort')).toBe('true');
    expect(met('needsLowercase')).toBe('true');
    expect(met('needsUppercase')).toBe('false');
    expect(met('needsDigit')).toBe('false');
    expect(met('needsSpecial')).toBe('false');
  });

  it('exposes each rule status as text for screen readers', () => {
    render(<PasswordRules password="abcdefgh" />);
    expect(screen.getByTestId('password-rule-needsLowercase')).toHaveTextContent('Met');
    expect(screen.getByTestId('password-rule-needsUppercase')).toHaveTextContent('Not met');
  });

  it('ticks everything for a valid password', () => {
    render(<PasswordRules password="Aa1!aaaa" />);
    for (const key of ['tooShort', 'needsUppercase', 'needsLowercase', 'needsDigit', 'needsSpecial']) {
      expect(met(key)).toBe('true');
    }
  });
});
