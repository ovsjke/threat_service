import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import exec from 'k6/execution';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8082';
const RPS = Number(__ENV.RPS || 1);
const MODE = __ENV.MODE || 'unique';

if (!['unique', 'repeated'].includes(MODE)) {
  throw new Error('MODE must be unique or repeated');
}

const scannerDuration = new Trend('scanner_reported_duration_ms');

const files = [];

for (let i = 0; i < 100; i++) {
  const ext = ['txt', 'json', 'bin'][i % 3];
  const filename = `file-${String(i).padStart(3, '0')}.${ext}`;

  const type = {
    txt: 'text/plain',
    json: 'application/json',
    bin: 'application/octet-stream',
  }[ext];

  files.push({
    filename,
    type,
    data: open(`./fixtures/generated/${filename}`, 'b'),
  });
}

export const options = {
  scenarios: {
    scan_load: {
      executor: 'constant-arrival-rate',
      rate: RPS,
      timeUnit: '1s',
      duration: '1m',
      preAllocatedVUs: 10,
      maxVUs: 20,
    },
  },
  thresholds: {
    checks: ['rate==1'],
    http_req_failed: ['rate==0'],
    dropped_iterations: ['count==0'],
  },
  summaryTrendStats: [
    'avg', 'min', 'med', 'max',
    'p(90)', 'p(95)', 'p(99)',
  ],
};

export default function () {
  const iteration = exec.scenario.iterationInTest;
  const file = files[(iteration * 37) % files.length];
  let payload = file.data;

  if (MODE === 'unique') {
    const bytes = new Uint8Array(file.data.slice(0));
    const nonce = String(iteration).padStart(16, '0').slice(-16);

    // Сохраняем корректное завершение JSON.
    const offset = file.type === 'application/json'
      ? bytes.length - 18
      : bytes.length - 16;

    for (let i = 0; i < 16; i++) {
      bytes[offset + i] = nonce.charCodeAt(i);
    }

    payload = bytes.buffer;
  }

  const response = http.post(
    `${BASE_URL}/scans`,
    {
      file: http.file(
        payload,
        file.filename,
        file.type
      ),
    },
    {
      timeout: '30s',
      tags: { name: 'POST /scans' },
    }
  );

  let body = null;
  try {
    body = response.json();
  } catch (_) {}

  check(response, {
    'scan completed and clean': (r) =>
      r.status === 200 && body?.verdict === 'clean',
  });

  if (typeof body?.duration_ms === 'number') {
    scannerDuration.add(body.duration_ms);
  }
}