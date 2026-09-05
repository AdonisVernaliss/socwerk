import { env } from '$env/dynamic/public';
import type { Handle } from '@sveltejs/kit';

export const handle: Handle = async ({ event, resolve }) => {
  const response = await resolve(event);
  const configuredApiUrl = env.PUBLIC_API_URL || 'http://localhost:8000';
  let apiOrigin = 'http://localhost:8000';
  try {
    const parsed = new URL(configuredApiUrl);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') apiOrigin = parsed.origin;
  } catch {
    // Keep the safe local default when deployment configuration is malformed.
  }

  const contentSecurityPolicy = response.headers.get('Content-Security-Policy');
  if (contentSecurityPolicy) {
    response.headers.set(
      'Content-Security-Policy',
      contentSecurityPolicy.replace(
        /connect-src ([^;]+)/,
        (_directive, sources: string) => `connect-src ${sources} ${apiOrigin}`
      )
    );
  }
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'no-referrer');
  response.headers.set('X-Frame-Options', 'DENY');
  return response;
};
