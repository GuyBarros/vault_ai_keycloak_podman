export function splitStreamBuffer(buffer: string): [string, string] {
  let trailing = 0;
  for (let i = buffer.length - 1; i >= 0; i--) {
    if (buffer[i] === '\\') trailing++;
    else break;
  }
  if (trailing % 2 === 0) return [buffer, ''];
  return [buffer.slice(0, -1), buffer.slice(-1)];
}
