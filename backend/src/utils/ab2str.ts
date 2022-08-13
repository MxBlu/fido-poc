
export function ab2str(ab: ArrayBuffer): string {
  return String.fromCharCode(...Array.from<number>(new Uint8Array(ab)));
}