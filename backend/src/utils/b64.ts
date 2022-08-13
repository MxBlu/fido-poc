
/**
 * Convert an ArrayBuffer or a string to a base-64 string
 * @param source ArrayBuffer or sting
 * @returns Base-64 string
 */
export function b64_encode(ab: ArrayBuffer | string): string {
  const buff = Buffer.from(<string> ab);
  return buff.toString('base64');
}

/**
 * Convert a base-64 string to an ArrayBuffer
 * @param b64 Base-64 string
 * @returns ArrayBuffer
 */
export function b64_decode(b64: string): ArrayBuffer {
  const buff = Buffer.from(b64, 'base64')
  return buff.buffer;
}

/**
 * Convert a base 64 string to a base 64 URL string
 * @param b64 Base 64 string
 * @returns Base 64 URL string
 */
export function b64_to_b64url(b64: string): string {
  return b64.replace(/-/g, '+').replace(/_/g, '/');
}

/**
 * Convert a base 64 URL string to a base 64 string
 * @param b64 Base 64 URL string
 * @returns Base 64 string
 */
 export function b64url_to_b64(b64: string): string {
  return b64.replace(/+/g, '-').replace(/\//g, '_');
}