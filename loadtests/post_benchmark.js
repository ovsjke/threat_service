import http from 'k6/http';
import { check } from 'k6';
import crypto from 'k6/crypto';
import exec from 'k6/execution';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8080';
const RPS = Number(__ENV.RPS || 30);
const RUN_ID = __ENV.RUN_ID;

if (!RUN_ID) {
  throw new Error('RUN_ID is required');
}

export const options = {
  scenarios: {
    post_load: {
      executor: 'constant-arrival-rate',
      rate: RPS,
      timeUnit: '1s',
      duration: '1m',
      preAllocatedVUs: 30,
      maxVUs: 30,
    },
  },

  thresholds: {
    checks: ['rate==1'],
    http_req_failed: ['rate<0.01'],
    dropped_iterations: ['count==0'],
  },

  summaryTrendStats: [
    'avg', 'min', 'med', 'max',
    'p(90)', 'p(95)', 'p(99)',
  ],
};

export default function () {
  const iteration = exec.scenario.iterationInTest;

  const payload = {
    md5: crypto.md5(
      `benchmark:post:${RUN_ID}:${iteration}`,
      'hex'
    ),
    name: `Benchmark Post ${iteration}`,
    description: `benchmark-post:${RUN_ID}`,
    severity: 'low',
  };

  const response = http.post(
    `${BASE_URL}/info`,
    JSON.stringify(payload),
    {
      headers: {
        'Content-Type': 'application/json',
      },
      tags: {
        name: 'POST /info',
      },
    }
  );

  check(response, {
    'POST returns 201': (r) => r.status === 201,
  });
}