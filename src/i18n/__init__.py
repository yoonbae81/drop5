"""
Internationalization (i18n) module for Drop5.
Supports 65+ languages with country-separated JSON files.
"""

from .i18n import (
    detect_language,
    get_translations,
    get_available_languages,
    get_native_language_info,
    SUPPORTED_LANGUAGES,
    DEFAULT_LANGUAGE,
    LANGUAGE_COOKIE_NAME,
    search_country
)

__all__ = [
    'detect_language',
    'get_translations',
    'get_available_languages',
    'get_native_language_info',
    'SUPPORTED_LANGUAGES',
    'DEFAULT_LANGUAGE',
    'LANGUAGE_COOKIE_NAME',
    'search_country'
]
