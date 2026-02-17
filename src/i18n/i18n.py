"""
Internationalization (i18n) module for Drop5.
Supports 65+ languages with country-separated JSON files.
"""

import json
import os
import ipaddress
from bottle import request

# Configuration
DEFAULT_LANGUAGE = 'en'
LANGUAGE_COOKIE_NAME = 'drop5_lang'
I18N_DIR = os.path.dirname(__file__)
LOCALES_DIR = os.path.join(I18N_DIR, "locales")
RSC_DIR = os.path.join(I18N_DIR, "rsc")
MAPPING_DATABASE = os.path.join(RSC_DIR, "mapping.db")

# Global cache for IP ranges
_ip_intervals = []

# Country to Language Mapping
# This is a simplified mapping. For countries not listed, it will fallback to DEFAULT_LANGUAGE.
COUNTRY_TO_LANG = {
    'KR': 'ko',
    'JP': 'ja',
    'CN': 'zh-CN',
    'TW': 'zh-TW',
    'HK': 'zh-TW',
    'MO': 'zh-TW',
    'FR': 'fr',
    'DE': 'de',
    'ES': 'es',
    'IT': 'it',
    'RU': 'ru',
    'BY': 'be',
    'UA': 'uk',
    'KZ': 'kk',
    'TR': 'tr',
    'BR': 'pt',
    'PT': 'pt',
    'VN': 'vi',
    'TH': 'th',
    'ID': 'id',
    'MY': 'ms',
    'PH': 'en',
    'IN': 'hi',
    'SA': 'ar',
    'AE': 'ar',
    'EG': 'ar',
    'IL': 'he',
    'PL': 'pl',
    'NL': 'nl',
    'SE': 'sv',
    'NO': 'nb',
    'DK': 'da',
    'FI': 'fi',
    'CZ': 'cs',
    'GR': 'el',
    'HU': 'hu',
    'RO': 'ro',
    'BG': 'bg',
    'SK': 'sk',
    'HR': 'hr',
    'RS': 'sr',
    'BA': 'bs',
    'ME': 'sr',
    'AL': 'sq',
    'IS': 'is',
    'EE': 'et',
    'LV': 'lv',
    'LT': 'lt',
    'GE': 'ka',
    'AM': 'hy',
    'AZ': 'az',
    'KH': 'km',
    'LA': 'lo',
    'MN': 'mn',
    'NP': 'ne',
    'PK': 'en',
    'IR': 'fa',
    'AF': 'ar', # Closest match
    'ZA': 'af',
}

# Language configuration with native names
LANGUAGE_CONFIG = {
    'af': {'name': 'Afrikaans'},
    'ar': {'name': 'العربية'},
    'az': {'name': 'Azərbaycanca'},
    'be': {'name': 'Беларуская'},
    'bg': {'name': 'Български'},
    'bs': {'name': 'Bosanski'},
    'ca': {'name': 'Català'},
    'cs': {'name': 'Čeština'},
    'cy': {'name': 'Cymraeg'},
    'da': {'name': 'Dansk'},
    'de': {'name': 'Deutsch'},
    'el': {'name': 'Ελληνικά'},
    'en': {'name': 'English'},
    'es': {'name': 'Español'},
    'et': {'name': 'Eesti'},
    'eu': {'name': 'Euskara'},
    'fa': {'name': 'فارسی'},
    'fi': {'name': 'Suomi'},
    'fr': {'name': 'Français'},
    'ga': {'name': 'Gaeilge'},
    'gl': {'name': 'Galego'},
    'he': {'name': 'עברית'},
    'hi': {'name': 'हिन्दी'},
    'hr': {'name': 'Hrvatski'},
    'hu': {'name': 'Magyar'},
    'hy': {'name': 'Հայերեն'},
    'id': {'name': 'Bahasa Indonesia'},
    'is': {'name': 'Íslenska'},
    'it': {'name': 'Italiano'},
    'ja': {'name': '日本語'},
    'ka': {'name': 'ქართული'},
    'kk': {'name': 'Қазақ тілі'},
    'km': {'name': 'ខ្មែរ'},
    'kn': {'name': 'ಕನ್ನಡ'},
    'ko': {'name': '한국어'},
    'lo': {'name': 'ลา우'},
    'lt': {'name': 'Lietuvių'},
    'lv': {'name': 'Latviešu'},
    'mk': {'name': 'Македонски'},
    'ml': {'name': 'മലയാളം'},
    'mn': {'name': 'Монгол'},
    'ms': {'name': 'Bahasa Melayu'},
    'nb': {'name': 'Norsk bokmål'},
    'ne': {'name': 'नेपाली'},
    'nl': {'name': 'Nederlands'},
    'nn': {'name': 'Norsk nynorsk'},
    'pl': {'name': 'Polski'},
    'pt': {'name': 'Português'},
    'ro': {'name': 'Română'},
    'ru': {'name': 'Русский'},
    'sk': {'name': 'Slovenčina'},
    'sl': {'name': 'Slovenščina'},
    'sq': {'name': 'Shqip'},
    'sr': {'name': 'Српски'},
    'sv': {'name': 'Svenska'},
    'sw': {'name': 'Kiswahili'},
    'ta': {'name': 'தமிழ்'},
    'th': {'name': 'ไทย'},
    'tr': {'name': 'Türkçe'},
    'uk': {'name': 'Українська'},
    'uz': {'name': 'Oʻzbekcha'},
    'vi': {'name': 'Tiếng Việt'},
    'zh-CN': {'name': '简体中文'},
    'zh-TW': {'name': '繁體中文'}
}


def get_flag_emoji(country_code):
    """Convert ISO-3166-1 alpha-2 country code to flag emoji."""
    if not country_code or len(country_code) != 2:
        return ""
    return "".join(chr(127397 + ord(c.upper())) for c in country_code)


def get_available_languages(include_info=False):
    """Get list of available language codes from JSON files."""
    languages = []
    if os.path.exists(LOCALES_DIR):
        for filename in os.listdir(LOCALES_DIR):
            if filename.endswith('.json'):
                lang_code = filename[:-5]  # Remove .json extension
                if include_info:
                    info = LANGUAGE_CONFIG.get(lang_code, {'name': lang_code})
                    languages.append({
                        'code': lang_code,
                        'name': info['name']
                    })
                else:
                    languages.append(lang_code)
    
    # Sort by name if info is included, otherwise by code
    if include_info:
        languages.sort(key=lambda x: x['name'])
    else:
        languages.sort()
    return languages


SUPPORTED_LANGUAGES = get_available_languages()

# Cache translations in memory
_translations_cache = {}


def load_translations(lang_code: str) -> dict:
    """Load translations for a specific language from its JSON file."""
    global _translations_cache
    
    # Check cache first
    if lang_code in _translations_cache:
        return _translations_cache[lang_code]
    
    # Load from file
    file_path = os.path.join(LOCALES_DIR, f'{lang_code}.json')
    
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            _translations_cache[lang_code] = json.load(f)
            return _translations_cache[lang_code]
    
    # Return empty dict if file not found
    return {}


def get_translations(lang_code: str) -> dict:
    """
    Get translations for a language code.
    Falls back to English if language not found.
    """
    translations = load_translations(lang_code)
    
    # If requested language has no translations, fall back to English
    if not translations and lang_code != DEFAULT_LANGUAGE:
        translations = load_translations(DEFAULT_LANGUAGE)
    
    return translations


def parse_accept_language(header: str) -> str:
    """
    Parse Accept-Language header and return best matching supported language.
    
    Example header: "en-US,en;q=0.9,ko;q=0.8"
    Returns: 'en', 'ko', or DEFAULT_LANGUAGE
    """
    if not header:
        return DEFAULT_LANGUAGE
    
    # Parse header: split by comma, then by semicolon to get lang and q-value
    languages = []
    for part in header.split(','):
        part = part.strip()
        if not part:
            continue
        
        # Parse "en-US;q=0.9" format
        if ';' in part:
            lang, q = part.split(';', 1)
            lang = lang.strip()
            # Extract q value (default 1.0)
            q = float(q.split('=')[1].strip()) if '=' in q else 1.0
        else:
            lang = part
            q = 1.0
        
        languages.append((lang, q))
    
    # Sort by q-value (descending)
    languages.sort(key=lambda x: -x[1])
    
    # Find first matching supported language
    for lang, _ in languages:
        # Check exact match (e.g., "en", "ko", "zh-TW")
        if lang in SUPPORTED_LANGUAGES:
            return lang
        # Check primary language code (e.g., "en-US" -> "en")
        primary = lang.split('-')[0]
        if primary in SUPPORTED_LANGUAGES:
            return primary
    
    return DEFAULT_LANGUAGE


def get_client_ip(request):
    """Extract client IP from request, handling proxies."""
    # Common headers used by reverse proxies
    for header in ['X-Forwarded-For', 'X-Real-IP']:
        ip = request.headers.get(header)
        if ip:
            # X-Forwarded-For can be a list: "client, proxy1, proxy2"
            return ip.split(',')[0].strip()
    return request.environ.get('REMOTE_ADDR')


def load_ip_database():
    """Load IP range database into memory."""
    global _ip_intervals
    if _ip_intervals:
        return True
    
    if not os.path.exists(MAPPING_DATABASE):
        return False
    
    try:
        with open(MAPPING_DATABASE, "r") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) == 3:
                    start_ip, end_ip, country = parts
                    _ip_intervals.append((int(start_ip), int(end_ip), country))
        return True
    except Exception as e:
        print(f"Error loading IP database: {e}")
        return False


def search_country(ip_str):
    """Search country code for a given IP string."""
    if not load_ip_database():
        return None
    
    try:
        search_ip = int(ipaddress.IPv4Address(ip_str))
    except (ValueError, ipaddress.AddressValueError):
        return None
    
    left, right = 0, len(_ip_intervals) - 1
    while left <= right:
        mid = (left + right) // 2
        start_ip, end_ip, country = _ip_intervals[mid]
        if start_ip <= search_ip <= end_ip:
            return country
        elif start_ip > search_ip:
            right = mid - 1
        else:
            left = mid + 1
    return None


def get_native_language_info(request):
    """Detect native language from IP and return its config."""
    ip = get_client_ip(request)
    country_code = search_country(ip)
    
    lang_code = COUNTRY_TO_LANG.get(country_code, DEFAULT_LANGUAGE)
    # If detected language is English or not supported, we might just use Korean as the "native" counterpart
    if lang_code == DEFAULT_LANGUAGE or lang_code not in SUPPORTED_LANGUAGES:
        # Check Accept-Language as fallback for "native"
        accept_lang = request.headers.get('Accept-Language', '')
        if accept_lang:
            detected = parse_accept_language(accept_lang)
            if detected in SUPPORTED_LANGUAGES and detected != DEFAULT_LANGUAGE:
                lang_code = detected
            else:
                lang_code = 'ko' # Default native fallback to Korean
        else:
            lang_code = 'ko' # Default native fallback to Korean
    
    info = LANGUAGE_CONFIG.get(lang_code, LANGUAGE_CONFIG['ko'])
    
    # Use detected country code for flag
    flag = get_flag_emoji(country_code) if country_code else ""
    
    return {
        'code': lang_code,
        'name': info['name'],
        'flag': flag
    }


def detect_language(request) -> str:
    """
    Detect user's preferred language using hybrid approach.
    
    Priority:
    1. Cookie (saved user preference)
    2. IP-based detection (native)
    3. Accept-Language header
    4. Default (English)
    """
    # 1. Check cookie for saved language preference
    lang_cookie = request.get_cookie(LANGUAGE_COOKIE_NAME)
    if lang_cookie and lang_cookie in SUPPORTED_LANGUAGES:
        return lang_cookie
    
    # 2. Check IP-based native language
    native_info = get_native_language_info(request)
    if native_info['code'] in SUPPORTED_LANGUAGES:
        return native_info['code']
    
    # 3. Check Accept-Language header
    accept_lang = request.headers.get('Accept-Language', '')
    if accept_lang:
        detected = parse_accept_language(accept_lang)
        if detected in SUPPORTED_LANGUAGES:
            return detected
    
    # 4. Fall back to default (English)
    return DEFAULT_LANGUAGE


