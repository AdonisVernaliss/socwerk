import { describe, expect, it } from 'vitest';
import { chooseLocale, messages, translate } from './i18n';

describe('localization', () => {
  it('has a complete German translation for every English key', () => {
    expect(Object.keys(messages.de).sort()).toEqual(Object.keys(messages.en).sort());
    expect(Object.values(messages.de).every((value) => value.length > 0)).toBe(true);
  });

  it('chooses German from browser language and otherwise English', () => {
    expect(chooseLocale('de-DE')).toBe('de');
    expect(chooseLocale('en-GB')).toBe('en');
    expect(translate('de', 'alerts')).toBe('Alarme');
  });
});
