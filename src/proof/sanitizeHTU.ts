/**
 * RFC 9449 §4.2: htu is the HTTP URI of the resource access request,
 * stripped of query and fragment so that the same proof is not bound to
 * specific query parameters.
 */
export function sanitizeHTU(htu: string): string {
  const url = new URL(htu);
  return `${url.origin}${url.pathname}`;
}
