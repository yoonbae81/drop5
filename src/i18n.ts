export const SUPPORTED_LOCALES = [
  'af', 'ar', 'az', 'be', 'bg', 'bs', 'ca', 'cs', 'cy', 'da', 'de', 'el', 'en', 'es', 'et', 'eu',
  'fa', 'fi', 'fr', 'ga', 'gl', 'he', 'hi', 'hr', 'hu', 'hy', 'id', 'is', 'it', 'ja', 'ka', 'kk',
  'km', 'kn', 'ko', 'lo', 'lt', 'lv', 'mk', 'ml', 'mn', 'ms', 'nb', 'ne', 'nl', 'nn', 'pl', 'pt',
  'ro', 'ru', 'sk', 'sl', 'sq', 'sr', 'sv', 'sw', 'ta', 'th', 'tr', 'uk', 'uz', 'vi', 'zh-CN', 'zh-TW',
] as const;

export type Locale = typeof SUPPORTED_LOCALES[number];
export type Translations = Record<string, string>;
export type TranslationParams = Record<string, string | number>;

const DEFAULT_LOCALE: Locale = 'en';
const localesByLowercase = new Map(SUPPORTED_LOCALES.map(locale => [locale.toLowerCase(), locale]));
const localeCache = new Map<Locale, Promise<Translations>>();

function supportedLocale(languageTag: string): Locale | null {
  const normalized = languageTag.trim().toLowerCase();
  if (!normalized || normalized === '*') return null;
  const exact = localesByLowercase.get(normalized);
  if (exact) return exact;
  return localesByLowercase.get(normalized.split('-')[0]) ?? null;
}

/**
 * Negotiate a supported locale from Accept-Language.
 *
 * A malformed q-value intentionally gets the HTTP default weight (1.0),
 * matching the Python implementation fixed in ff63f24 instead of throwing or
 * silently demoting the language.
 */
export function negotiateLocale(header: string | null): Locale {
  if (!header) return DEFAULT_LOCALE;

  const candidates = header.split(',').flatMap((part, index) => {
    const [languageTag, ...parameters] = part.trim().split(';');
    if (!languageTag) return [];
    const qualityParameter = parameters.find(parameter => /^\s*q\s*=/i.test(parameter));
    const qualityText = qualityParameter?.split('=', 2)[1]?.trim();
    const parsedQuality = qualityText ? Number(qualityText) : qualityParameter ? Number.NaN : 1;
    const quality = Number.isFinite(parsedQuality) ? parsedQuality : 1;
    return [{ languageTag, quality, index }];
  });

  candidates.sort((left, right) => right.quality - left.quality || left.index - right.index);
  for (const candidate of candidates) {
    const locale = supportedLocale(candidate.languageTag);
    if (locale) return locale;
  }
  return DEFAULT_LOCALE;
}

export function requestLocale(request: Request): Locale {
  // Priority matches the Python original: saved cookie preference first,
  // then the Accept-Language header.
  const cookieHeader = request.headers.get('cookie');
  if (cookieHeader) {
    const match = cookieHeader.match(/(?:^|;\s*)drop5_lang=([A-Za-z-]+)/);
    if (match) {
      const locale = supportedLocale(match[1]);
      if (locale) return locale;
    }
  }
  return negotiateLocale(request.headers.get('accept-language'));
}

async function fetchLocale(assets: Fetcher, requestUrl: string, locale: Locale): Promise<Translations> {
  let pending = localeCache.get(locale);
  if (!pending) {
    pending = (async () => {
      const response = await assets.fetch(new Request(new URL(`/locales/${locale}.json`, requestUrl)));
      if (!response.ok) throw new Error(`Locale asset ${locale} returned ${response.status}`);
      return response.json<Translations>();
    })();
    localeCache.set(locale, pending);
    pending.catch(() => localeCache.delete(locale));
  }
  return pending;
}

export async function requestTranslations(
  request: Request,
  assets: Fetcher,
): Promise<{ locale: Locale; translations: Translations }> {
  const locale = requestLocale(request);
  const englishPromise = fetchLocale(assets, request.url, DEFAULT_LOCALE);
  if (locale === DEFAULT_LOCALE) return { locale, translations: await englishPromise };

  const [english, selected] = await Promise.all([
    englishPromise,
    fetchLocale(assets, request.url, locale).catch(() => ({})),
  ]);
  return { locale, translations: { ...english, ...selected } };
}

export function interpolate(template: string, params: TranslationParams = {}): string {
  return template.replace(/\{\{([A-Za-z0-9_]+)\}\}|\{([A-Za-z0-9_]+)\}/g, (token, doubleKey, singleKey) => {
    const key = doubleKey ?? singleKey;
    return Object.hasOwn(params, key) ? String(params[key]) : token;
  });
}

export function translate(
  translations: Translations,
  key: string,
  fallback: string,
  params: TranslationParams = {},
): string {
  return interpolate(translations[key] ?? fallback, params);
}

export function localeHeaders(locale: Locale): HeadersInit {
  return { 'content-language': locale, vary: 'Accept-Language' };
}
