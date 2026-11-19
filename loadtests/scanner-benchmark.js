import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8082';
const RPS = Number(__ENV.RPS || 1);

const fileData = open('./fixtures/clean-128kb.txt', 'b');

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
  const response = http.post(
    `${BASE_URL}/scans`,
    {
      file: http.file(
        fileData,
        'clean-128kb.txt',
        'text/plain'
      ),
    },
    {
      timeout: '30s',
      tags: {
        name: 'POST /scans',
      },
    }
  );

  check(response, {
    'scan successful': (r) =>
      r.status >= 200 && r.status < 300,
  });
}