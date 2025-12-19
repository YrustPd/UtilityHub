export function jsonResponse(payload, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=UTF-8',
      ...extraHeaders,
    },
  });
}

export function htmlResponse(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=UTF-8',
      ...extraHeaders,
    },
  });
}

export function textResponse(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=UTF-8',
      ...extraHeaders,
    },
  });
}

export function nowIso() {
  return new Date().toISOString();
}

export function randomId(length = 8) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join('');
}

export function utf8ToBytes(text) {
  return new TextEncoder().encode(text);
}

export function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

export function base64Encode(text) {
  const bytes = utf8ToBytes(text);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

export function base64Decode(str) {
  try {
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytesToUtf8(bytes);
  } catch (error) {
    return null;
  }
}

export function hexEncode(text) {
  const bytes = utf8ToBytes(text);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexDecode(hex) {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    return null;
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  try {
    return bytesToUtf8(bytes);
  } catch (error) {
    return null;
  }
}

export function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

export function base64ToBytes(str) {
  try {
    const binary = atob(str);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  } catch (error) {
    return null;
  }
}

export function base64UrlEncode(bytes) {
  const b64 = bytesToBase64(bytes);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlDecode(str) {
  const normalized = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const padded = normalized + padding;
  const bytes = base64ToBytes(padded);
  if (!bytes) return null;
  return bytesToUtf8(bytes);
}

export function anonymizeIp(ip) {
  if (!ip) return null;
  if (ip.includes(':')) {
    const parts = ip.split(':').filter((p) => p.length > 0);
    const prefix = parts.slice(0, 4).join(':');
    return `${prefix}::`;
  }
  const octets = ip.split('.');
  if (octets.length === 4) {
    octets[3] = '0';
    return octets.join('.');
  }
  return ip;
}

// Minimal QR Code generator (Byte mode only), adapted from public-domain implementations.
const QRCODE_ECC = {
  L: 1,
  M: 0,
  Q: 3,
  H: 2,
};

function qrPolynomialMultiply(p, q, mod) {
  const result = new Array(p.length + q.length - 1).fill(0);
  for (let i = 0; i < p.length; i += 1) {
    for (let j = 0; j < q.length; j += 1) {
      result[i + j] ^= qrGfMul(p[i], q[j], mod);
    }
  }
  return result;
}

function qrGfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i -= 1) {
    z = (z << 1) ^ ((z >> 7) * 0x11d);
    z &= 0xff;
    if (((y >>> i) & 1) !== 0) {
      z ^= x;
    }
  }
  return z;
}

function qrGenerateEccPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i += 1) {
    poly = qrPolynomialMultiply(poly, [1, qrGfExp(i)], 0x11d);
  }
  return poly;
}

function qrGfExp(n) {
  let x = 1;
  for (let i = 0; i < n; i += 1) {
    x = qrGfMul(x, 2);
  }
  return x;
}

function qrReedSolomonCompute(remainder, generator) {
  for (let i = 0; i < remainder.length; i += 1) remainder[i] = 0;
  return (data) => {
    for (const b of data) {
      const factor = b ^ remainder.shift();
      remainder.push(0);
      generator.forEach((coef, j) => {
        remainder[j] ^= qrGfMul(coef, factor);
      });
    }
  };
}

function qrGetAlignmentPatternPositions(version) {
  if (version === 1) return [];
  const posCount = Math.floor(version / 7) + 2;
  const size = version * 4 + 17;
  const step = version === 32 ? 26 : Math.ceil((size - 13) / (posCount * 2 - 2)) * 2;
  const result = [6];
  for (let i = 0; i < posCount - 1; i += 1) {
    result.push(size - 7 - i * step);
  }
  return result.reverse();
}

function qrMakeMatrix(version, dataCodewords, eccCodewords, mask) {
  const size = version * 4 + 17;
  const matrix = Array.from({ length: size }, () => Array(size).fill(null));

  function reserve(x, y, value) {
    matrix[y][x] = value;
  }

  function drawFinder(x, y) {
    for (let dy = -1; dy <= 7; dy += 1) {
      for (let dx = -1; dx <= 7; dx += 1) {
        const xx = x + dx;
        const yy = y + dy;
        if (xx < 0 || xx >= size || yy < 0 || yy >= size) continue;
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        reserve(xx, yy, dist !== 2 && dist !== 4 ? dist <= 1 : false);
      }
    }
  }

  function drawAlignment(x, y) {
    for (let dy = -2; dy <= 2; dy += 1) {
      for (let dx = -2; dx <= 2; dx += 1) {
        reserve(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }

  drawFinder(0, 0);
  drawFinder(size - 7, 0);
  drawFinder(0, size - 7);

  for (let i = 8; i < size - 8; i += 1) {
    reserve(i, 6, i % 2 === 0);
    reserve(6, i, i % 2 === 0);
  }

  const alignPositions = qrGetAlignmentPatternPositions(version);
  alignPositions.forEach((row) => {
    alignPositions.forEach((col) => {
      if (
        (row === 6 && col === 6) ||
        (row === 6 && col === size - 7) ||
        (row === size - 7 && col === 6)
      ) {
        return;
      }
      drawAlignment(col, row);
    });
  });

  function drawCodewords(bits) {
    let i = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right -= 1;
      for (let vert = 0; vert < size; vert += 1) {
        for (let j = 0; j < 2; j += 1) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? size - 1 - vert : vert;
          if (matrix[y][x] !== null) continue;
          matrix[y][x] = i < bits.length && bits[i] === 1;
          i += 1;
        }
      }
    }
  }

  function applyMask(maskPattern) {
    for (let y = 0; y < size; y += 1) {
      for (let x = 0; x < size; x += 1) {
        const cell = matrix[y][x];
        if (cell === null || cell === undefined) continue;
        let invert = false;
        switch (maskPattern) {
          case 0:
            invert = (x + y) % 2 === 0;
            break;
          case 1:
            invert = y % 2 === 0;
            break;
          case 2:
            invert = x % 3 === 0;
            break;
          case 3:
            invert = (x + y) % 3 === 0;
            break;
          case 4:
            invert = (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
            break;
          case 5:
            invert = ((x * y) % 2) + ((x * y) % 3) === 0;
            break;
          case 6:
            invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
            break;
          case 7:
            invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
            break;
        }
        if (invert) matrix[y][x] = !cell;
      }
    }
  }

  drawCodewords([...dataCodewords, ...eccCodewords].flatMap((byte) => {
    const bits = [];
    for (let i = 7; i >= 0; i -= 1) bits.push((byte >>> i) & 1);
    return bits;
  }));

  applyMask(mask);
  return matrix;
}

function qrAddFormatInfo(matrix, ecc, mask) {
  const size = matrix.length;
  const format = qrGetFormatBits(ecc, mask);
  for (let i = 0; i <= 5; i += 1) matrix[8][i] = ((format >>> i) & 1) === 1;
  matrix[8][7] = ((format >>> 6) & 1) === 1;
  matrix[8][8] = ((format >>> 7) & 1) === 1;
  matrix[7][8] = ((format >>> 8) & 1) === 1;
  for (let i = 9; i <= 14; i += 1) matrix[14 - i][8] = ((format >>> i) & 1) === 1;

  for (let i = 0; i <= 7; i += 1) matrix[size - 1 - i][8] = ((format >>> i) & 1) === 1;
  for (let i = 8; i <= 14; i += 1) matrix[8][size - 15 + i] = ((format >>> i) & 1) === 1;
}

function qrGetFormatBits(ecc, mask) {
  const ecbits = ecc;
  const data = (ecbits << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i += 1) rem = (rem << 1) ^ (((rem >>> 9) * 0x537) & 0x7ff);
  const bits = ((data << 10) | rem) ^ 0x5412;
  return bits & 0x7fff;
}

function qrInterleaveBlocks(blocks) {
  const maxLen = Math.max(...blocks.map((b) => b.length));
  const result = [];
  for (let i = 0; i < maxLen; i += 1) {
    blocks.forEach((b) => {
      if (i < b.length) result.push(b[i]);
    });
  }
  return result;
}

function qrGetVersion(textBytes, eccLevel) {
  // Byte mode capacity table for ECC M up to version 10; scale down for other ECC levels by known ratios.
  const capacitiesM = [0, 14, 26, 42, 62, 84, 106, 122, 152, 180, 213]; // index is version
  const adjust = { 0: 1.0, 1: 1.33, 2: 0.8, 3: 0.66 }; // approximate scaling for L/M/Q/H
  for (let v = 1; v <= 10; v += 1) {
    const capacity = Math.floor(capacitiesM[v] * adjust[eccLevel] || capacitiesM[v]);
    if (textBytes.length <= capacity) return v;
  }
  return null;
}

function qrEncodeBytes(bytes, version, eccLevel) {
  const modeIndicator = [0, 1, 0, 0]; // Byte mode
  const cciBits = version < 10 ? 8 : version < 27 ? 16 : 16;
  const bits = [...modeIndicator];
  for (let i = cciBits - 1; i >= 0; i -= 1) bits.push((bytes.length >>> i) & 1);
  bytes.forEach((b) => {
    for (let i = 7; i >= 0; i -= 1) bits.push((b >>> i) & 1);
  });
  const totalDataBits = qrGetTotalDataCodewords(version, eccLevel) * 8;
  const terminator = Math.min(4, totalDataBits - bits.length);
  for (let i = 0; i < terminator; i += 1) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  const padBytes = [0xec, 0x11];
  let padIndex = 0;
  while (bits.length < totalDataBits) {
    const byte = padBytes[padIndex % 2];
    for (let i = 7; i >= 0 && bits.length < totalDataBits; i -= 1) bits.push((byte >>> i) & 1);
    padIndex += 1;
  }
  const dataBytes = [];
  for (let i = 0; i < bits.length; i += 8) {
    let val = 0;
    for (let j = 0; j < 8; j += 1) val = (val << 1) | bits[i + j];
    dataBytes.push(val);
  }
  return dataBytes;
}

function qrGetTotalDataCodewords(version, eccLevel) {
  // Table for versions 1-10 for simplicity.
  const table = {
    1: [19, 16, 13, 9],
    2: [34, 28, 22, 16],
    3: [55, 44, 34, 26],
    4: [80, 64, 48, 36],
    5: [108, 86, 62, 46],
    6: [136, 108, 76, 60],
    7: [156, 124, 88, 66],
    8: [194, 154, 110, 86],
    9: [232, 182, 132, 100],
    10: [274, 216, 154, 122],
  };
  return table[version]?.[eccLevel] || 0;
}

function qrGetBlockInfo(version, eccLevel) {
  // Version 1-10 block info for simplicity.
  const table = {
    1: {
      0: { blocks: 1, codewords: 19, ec: 7 },
      1: { blocks: 1, codewords: 16, ec: 10 },
      2: { blocks: 1, codewords: 13, ec: 13 },
      3: { blocks: 1, codewords: 9, ec: 17 },
    },
    2: {
      0: { blocks: 1, codewords: 34, ec: 10 },
      1: { blocks: 1, codewords: 28, ec: 16 },
      2: { blocks: 1, codewords: 22, ec: 22 },
      3: { blocks: 1, codewords: 16, ec: 28 },
    },
    3: {
      0: { blocks: 1, codewords: 55, ec: 15 },
      1: { blocks: 1, codewords: 44, ec: 26 },
      2: { blocks: 2, codewords: 17, ec: 18 },
      3: { blocks: 2, codewords: 13, ec: 22 },
    },
    4: {
      0: { blocks: 1, codewords: 80, ec: 20 },
      1: { blocks: 2, codewords: 32, ec: 18 },
      2: { blocks: 2, codewords: 24, ec: 26 },
      3: { blocks: 4, codewords: 9, ec: 16 },
    },
    5: {
      0: { blocks: 1, codewords: 108, ec: 26 },
      1: { blocks: 2, codewords: 43, ec: 24 },
      2: { blocks: 2, codewords: 15, ec: 18 },
      3: { blocks: 2, codewords: 11, ec: 22 },
    },
    6: {
      0: { blocks: 2, codewords: 68, ec: 18 },
      1: { blocks: 4, codewords: 27, ec: 16 },
      2: { blocks: 4, codewords: 19, ec: 24 },
      3: { blocks: 4, codewords: 15, ec: 28 },
    },
    7: {
      0: { blocks: 2, codewords: 78, ec: 20 },
      1: { blocks: 4, codewords: 31, ec: 18 },
      2: { blocks: 2, codewords: 14, ec: 18 },
      3: { blocks: 4, codewords: 13, ec: 26 },
    },
    8: {
      0: { blocks: 2, codewords: 97, ec: 24 },
      1: { blocks: 2, codewords: 38, ec: 22 },
      2: { blocks: 4, codewords: 18, ec: 22 },
      3: { blocks: 4, codewords: 14, ec: 26 },
    },
    9: {
      0: { blocks: 2, codewords: 116, ec: 30 },
      1: { blocks: 3, codewords: 36, ec: 22 },
      2: { blocks: 4, codewords: 16, ec: 20 },
      3: { blocks: 4, codewords: 12, ec: 24 },
    },
    10: {
      0: { blocks: 2, codewords: 68, ec: 18 },
      1: { blocks: 4, codewords: 43, ec: 26 },
      2: { blocks: 6, codewords: 19, ec: 24 },
      3: { blocks: 6, codewords: 15, ec: 28 },
    },
  };
  return table[version]?.[eccLevel];
}

function qrEncode(textBytes, eccLevel) {
  const version = qrGetVersion(textBytes, eccLevel);
  if (!version) return null;
  const blockInfo = qrGetBlockInfo(version, eccLevel);
  if (!blockInfo) return null;

  const dataBytes = qrEncodeBytes(textBytes, version, eccLevel);

  const blocks = [];
  let offset = 0;
  for (let i = 0; i < blockInfo.blocks; i += 1) {
    const cwCount = blockInfo.codewords;
    const chunk = dataBytes.slice(offset, offset + cwCount);
    offset += cwCount;
    const gen = qrGenerateEccPoly(blockInfo.ec);
    const remainder = new Array(gen.length - 1).fill(0);
    qrReedSolomonCompute(remainder, gen)(chunk);
    blocks.push({ data: chunk, ecc: remainder });
  }

  const data = qrInterleaveBlocks(blocks.map((b) => b.data));
  const ecc = qrInterleaveBlocks(blocks.map((b) => b.ecc));

  let bestMask = 0;
  let bestPenalty = Infinity;
  let bestMatrix = null;

  for (let mask = 0; mask < 8; mask += 1) {
    const matrix = qrMakeMatrix(version, data, ecc, mask);
    qrAddFormatInfo(matrix, eccLevel, mask);
    const penalty = qrPenalty(matrix);
    if (penalty < bestPenalty) {
      bestPenalty = penalty;
      bestMask = mask;
      bestMatrix = matrix;
    }
  }

  return { matrix: bestMatrix, version };
}

function qrPenalty(matrix) {
  const size = matrix.length;
  let score = 0;

  // Adjacent modules in row/column
  for (let y = 0; y < size; y += 1) {
    let run = 1;
    for (let x = 1; x < size; x += 1) {
      if (matrix[y][x] === matrix[y][x - 1]) {
        run += 1;
        if (run === 5) score += 3;
        else if (run > 5) score += 1;
      } else run = 1;
    }
  }
  for (let x = 0; x < size; x += 1) {
    let run = 1;
    for (let y = 1; y < size; y += 1) {
      if (matrix[y][x] === matrix[y - 1][x]) {
        run += 1;
        if (run === 5) score += 3;
        else if (run > 5) score += 1;
      } else run = 1;
    }
  }

  // 2x2 blocks
  for (let y = 0; y < size - 1; y += 1) {
    for (let x = 0; x < size - 1; x += 1) {
      const c = matrix[y][x];
      if (c === matrix[y][x + 1] && c === matrix[y + 1][x] && c === matrix[y + 1][x + 1]) score += 3;
    }
  }

  // Patterns
  const pattern1 = [true, false, true, true, true, false, true];
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x <= size - 7; x += 1) {
      const segment = matrix[y].slice(x, x + 7);
      if (segment.every((v, i) => v === pattern1[i])) score += 40;
      const segmentInv = segment.map((v) => !v);
      if (segmentInv.every((v, i) => v === pattern1[i])) score += 40;
    }
  }
  for (let x = 0; x < size; x += 1) {
    for (let y = 0; y <= size - 7; y += 1) {
      const segment = [];
      for (let k = 0; k < 7; k += 1) segment.push(matrix[y + k][x]);
      if (segment.every((v, i) => v === pattern1[i])) score += 40;
      const segmentInv = segment.map((v) => !v);
      if (segmentInv.every((v, i) => v === pattern1[i])) score += 40;
    }
  }

  // Dark module ratio
  let dark = 0;
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      if (matrix[y][x]) dark += 1;
    }
  }
  const total = size * size;
  const k = Math.abs(dark * 20 - total * 10) / total; // proportion*100 - 50
  score += Math.floor(k) * 10;
  return score;
}

export function generateQrSvg(text, eccLevel = 'M', scale = 6, margin = 4) {
  const ecc = QRCODE_ECC[eccLevel] ?? QRCODE_ECC.M;
  const bytes = utf8ToBytes(text);
  const qr = qrEncode(bytes, ecc);
  if (!qr) return null;
  const { matrix } = qr;
  const size = matrix.length;
  const dim = (size + margin * 2) * scale;
  let path = '';
  for (let y = 0; y < size; y += 1) {
    let runStart = -1;
    for (let x = 0; x <= size; x += 1) {
      const isDark = x < size && matrix[y][x];
      if (isDark && runStart === -1) runStart = x;
      if ((!isDark || x === size) && runStart !== -1) {
        const x0 = (runStart + margin) * scale;
        const y0 = (y + margin) * scale;
        const w = (x - runStart) * scale;
        path += `M${x0} ${y0}h${w}v${scale}h-${w}z`;
        runStart = -1;
      }
    }
  }
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges"><path fill="#000" d="${path}"/></svg>`;
  return { svg, modules: size };
}
