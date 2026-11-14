import { Check, Circle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { PASSWORD_RULES } from '../utils/password';

/**
 * The password rules, shown before the user types, each ticked live as the
 * password meets it. Purely advisory: the server still validates.
 */
export function PasswordRules({ password, className = '' }: { password: string; className?: string }) {
  const { t } = useTranslation();
  return (
    <div className={`text-xs text-bambu-gray ${className}`}>
      <p className="mb-1">{t('passwordRules.title')}</p>
      <ul className="space-y-0.5">
        {PASSWORD_RULES.map((rule) => {
          const met = rule.test(password);
          return (
            <li
              key={rule.key}
              data-testid={`password-rule-${rule.key}`}
              data-met={met}
              className={`flex items-center gap-1.5 ${met ? 'text-bambu-green' : ''}`}
            >
              {met ? <Check className="w-3 h-3" aria-hidden="true" /> : <Circle className="w-3 h-3" aria-hidden="true" />}
              {t(`passwordRules.${rule.labelKey}`)}
              <span className="sr-only">{met ? t('passwordRules.met') : t('passwordRules.unmet')}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
