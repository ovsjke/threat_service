import http from 'k6/http';
import { check } from 'k6';
import crypto from 'k6/crypto';
import exec from 'k6/execution';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8080';
const RPS = Number(__ENV.RPS || 30);

export const options = {
  scenarios: {
    get_load: {
        executor: 'constant-arrival-rate',
        rate: RPS,
        timeUnit: '1s',
        duration: '1m',
        preAllocatedVUs: 100,
        maxVUs: 100,
    },
  },

  thresholds: {
    checks: ['rate==1'],
    http_req_failed: ['rate<0.01'],
    dropped_iterations: ['count==0'],
  },
  summaryTrendStats: [
  'avg',
  'min',
  'med',
  'max',
  'p(90)',
  'p(95)',
  'p(99)',
],
};

// Детерминированное перемешивание чисел.
function mix32(x) {
  x = Math.imul(x ^ (x >>> 16), 0x7feb352d);
  x = Math.imul(x ^ (x >>> 15), 0x846ca68b);
  return (x ^ (x >>> 16)) >>> 0;
}

export default function () {
  const iteration = exec.scenario.iterationInTest;

  // Доля каждой группы повторяется каждые 100 итераций.
  const bucket = (iteration * 37 + 17) % 100;
  const randomValue = mix32(iteration + 12345);

  let group;
  let value;
  let expectedStatus = 200;

  if (bucket < 60) {
    group = 'hot';
    value = 'benchmark:' + (1 + randomValue % 100);
  } else if (bucket < 85) {
    group = 'warm';
    value = 'benchmark:' + (101 + randomValue % 900);
  } else if (bucket < 95) {
    group = 'cold';
    value = 'benchmark:' + (1001 + randomValue % 9000);;
  } else {
    group = 'missing';
    value = 'benchmark:missing:' + randomValue;
    expectedStatus = 404;
  }

  const md5 = crypto.md5(value, 'hex');

  const response = http.get(
    `${BASE_URL}/info/${md5}`,
    {
      tags: {
        name: 'GET /info/{md5}',
        dataset: group,
      },
      responseCallback: http.expectedStatuses(expectedStatus),
    }
  );

  check(response, {
    'expected HTTP status': (r) => r.status === expectedStatus,
  });
}