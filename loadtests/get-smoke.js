import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 2,
  duration: '20s',

  thresholds: {
    http_req_failed: ['rate<0.01'],
    checks: ['rate==1'],
  },
};

const BASE_URL = 'http://127.0.0.1:8080';
const MD5 = __ENV.MD5;

export default function () {
  const response = http.get(
    `${BASE_URL}/info/${MD5}`
  );

  check(response, {
    'GET returns 200': (r) => r.status === 200,
  });

  sleep(0.2);
}