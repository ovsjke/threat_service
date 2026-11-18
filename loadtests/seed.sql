INSERT INTO threats (
    md5,
    name,
    description,
    severity
)
SELECT
    md5('benchmark:' || n::text),
    'Benchmark threat ' || n,
    'Generated benchmark fixture',
    (ARRAY['low', 'medium', 'high', 'critical'])[(n % 4) + 1]
FROM generate_series(10001, 100000) AS g(n)
ON CONFLICT (md5) DO NOTHING;

ANALYZE threats;