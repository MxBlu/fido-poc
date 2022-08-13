
/**
 * Convert an ArrayBuffer or a string to a base-64 string
 * @param source ArrayBuffer or sting
 * @returns Base-64 string
 */
export function b64_encode(ab: ArrayBuffer | string): string {
  let buff: Buffer = null;
  buff = Buffer.from(<string> ab);
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