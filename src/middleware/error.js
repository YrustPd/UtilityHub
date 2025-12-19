import { jsonResponse } from '../helpers/utils.js';

export function handleError(error, { isApi = true, requestId } = {}) {
  const status = Number(error?.status) || 500;
  const code = error?.code || 'internal_error';
  const message =
    error?.message && typeof error.message === 'string'
      ? error.message
      : 'An unexpected error occurred';

  if (!isApi) {
    return new Response('Something went wrong', {
      status,
      headers: { 'Cache-Control': 'no-store' },
    });
  }

  return jsonResponse(
    { error: { code, message }, requestId },
    status,
    { 'Cache-Control': 'no-store' }
  );
}
