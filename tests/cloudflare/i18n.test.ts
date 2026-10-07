import { env } from 'cloudflare:workers';
import { reset } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';
import {
  SUPPORTED_LOCALES,
  interpolate,
  negotiateLocale,
} from '../../src/i18n';
import worker, { type Env } from '../../src/worker';

const origin = 'https://drop5.test';

function request(path: string, init?: RequestInit, testEnv: Env = env): Promise<Response> {
  return worker.fetch(new Request(`${origin}${path}`, init), testEnv);
}

afterEach(async () => {
  await reset();
});

describe('Cloudflare i18n', () => {
  it('negotiates supported languages and preserves malformed-q fallback semantics', () => {
    expect(negotiateLocale('fr-CA;q=0.7,ko-KR;q=0.9,en;q=0.8')).toBe('ko');
    expect(negotiateLocale('zh-TW,zh-CN;q=0.9')).toBe('zh-TW');
    expect(negotiateLocale('ko;q=not-a-number,en;q=0.9')).toBe('ko');
    expect(negotiateLocale('ko;q=,en;q=0.9')).toBe('ko');
    expect(negotiateLocale('xx-YY,de;q=0.5')).toBe('de');
    expect(negotiateLocale('xx-YY')).toBe('en');
  });

  it('serves a negotiated session shell while keeping locale payloads external', async () => {
    const response = await request('/localized-session', {
      headers: { 'accept-language': 'ko-KR, en;q=0.8' },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get('content-language')).toBe('ko');
    expect(response.headers.get('vary')).toContain('Accept-Language');
    const html = await response.text();
    expect(html).toContain('<html lang="ko">');
    expect(html).toContain('data-i18n="upload_text"');
    expect(html).toContain('파일 업로드');
    expect(html).toContain('보내고 싶은 내용을 입력하세요.');
    expect(html).not.toContain('__MAX_FILE_SIZE__');
    expect(html).not.toContain('"upload_text":');

    const fallback = await request('/fallback-session', {
      headers: { 'accept-language': 'xx-YY' },
    });
    expect(fallback.status).toBe(200);
    expect(fallback.headers.get('content-language')).toBe('en');
    const fallbackHtml = await fallback.text();
    expect(fallbackHtml).toContain('<html lang="en">');
    expect(fallbackHtml).toContain('Upload Files');
  });

  it('publishes every main-branch locale and keeps the latest single-brace tokens', async () => {
    const responses = await Promise.all(SUPPORTED_LOCALES.map(locale => request(`/locales/${locale}.json`)));
    expect(responses.every(response => response.status === 200)).toBe(true);

    const english = await responses[SUPPORTED_LOCALES.indexOf('en')].json<Record<string, string>>();
    const korean = await responses[SUPPORTED_LOCALES.indexOf('ko')].json<Record<string, string>>();
    expect(english.upload_progress_single).toContain('{percent}');
    expect(english.upload_progress_single).not.toContain('{{percent}}');
    expect(english.upload_progress_multiple).toContain('{count}');
    expect(english.file_too_large_with_max).toContain('{filename}');
    expect(korean.file_too_large_with_max).toBe('{filename} 파일이 너무 큽니다 (최대 {max_mb}MB)');
    expect(interpolate(korean.file_too_large_with_max, { filename: '큰.txt', max_mb: 30 }))
      .toBe('큰.txt 파일이 너무 큽니다 (최대 30MB)');
  });

  it('returns a localized per-file 413 response with interpolation metadata', async () => {
    const oneMiB = 1024 * 1024;
    const testEnv = Object.assign(Object.create(env) as Env, {
      MAX_FILE_SIZE: String(oneMiB),
    });
    const form = new FormData();
    form.append('content', new File([new Uint8Array(oneMiB + 1)], '큰-하나.txt'));
    form.append('content', new File([new Uint8Array(oneMiB + 2)], '큰-둘.txt'));

    const response = await request('/localized-session/upload', {
      method: 'POST',
      headers: { 'accept-language': 'ko-KR, en;q=0.8' },
      body: form,
    }, testEnv);

    expect(response.status).toBe(413);
    expect(response.headers.get('content-language')).toBe('ko');
    const payload = await response.json<Record<string, any>>();
    expect(payload).toMatchObject({
      success: false,
      errorKey: 'file_too_large_with_max',
      errorParams: { filename: '큰-하나.txt', max_mb: 1 },
      files: [
        { name: '큰-하나.txt', size: oneMiB + 1, maxBytes: oneMiB },
        { name: '큰-둘.txt', size: oneMiB + 2, maxBytes: oneMiB },
      ],
    });
    expect(payload.error).toContain('큰-하나.txt 파일이 너무 큽니다 (최대 1MB)');
    expect(payload.error).toContain('큰-둘.txt 파일이 너무 큽니다 (최대 1MB)');
  });
});
