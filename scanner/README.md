# Scanner Service

Самостоятельный HTTP-сервис: принимает один файл, вычисляет MD5 и SHA-256 за один
проход и передаёт байты в постоянно работающий ClamAV через TCP `INSTREAM`.
Файлы не сохраняются. При заданном `THREAT_GRPC_ADDR` результат дополняется
сведениями из Threat API по MD5. Для заражённого файла без записи создаётся
угроза с именем сигнатуры ClamAV, описанием `Detected by ClamAV` и severity `medium`
(ClamAV не предоставляет оценку severity).

## Запуск

Из корня репозитория (нужен Docker Compose с поддержкой `include`):

```sh
docker compose up -d --build app_api scanner
docker compose logs -f scanner clamav
```

Для полного pipeline нужны `.env` с параметрами PostgreSQL (см. корневой
`.env.example`) и сервис `app_api`. Для отдельного Compose-проекта без каталога:

```sh
docker compose -f scanner/docker-compose.yml up -d --build scanner
```

Выберите один из этих вариантов, поскольку оба публикуют один HTTP-порт.
При первом старте ClamAV загружает и обновляет сигнатуры, это может занять несколько
минут. Сканер запускается после успешного `PING` движка. Сигнатуры сохраняются в
именованном volume `clamav_data`; FreshClam обновляет их в контейнере.
Порт clamd не публикуется; Scanner подключён также к общей сети Threat API.
В отдельном Compose-проекте адрес `app_api` недоступен: Scanner вернёт
`catalog_status: unavailable`, сохранив результат ClamAV.
Для загрузки обновлений ClamAV нужен доступ в интернет. Желательно выделить Docker
не менее 4 GiB RAM. Официальный образ `clamav/clamav:1.4` запускается с
`platform: linux/amd64`: на Apple Silicon нужна включённая эмуляция amd64.

```sh
curl -fsS http://127.0.0.1:8082/health
curl -fsS http://127.0.0.1:8082/ready
printf 'hello scanner\n' > /tmp/scanner-clean.txt
curl --fail-with-body -F 'file=@/tmp/scanner-clean.txt' http://127.0.0.1:8082/scans
```

EICAR — безопасная стандартная тестовая строка антивирусов:

```sh
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/scanner-eicar.txt
curl --fail-with-body -F 'file=@/tmp/scanner-eicar.txt' http://127.0.0.1:8082/scans
rm /tmp/scanner-clean.txt /tmp/scanner-eicar.txt
```

Чистый файл даёт `verdict: "clean"`, EICAR — `verdict: "infected"` и непустую
`signature` (точное имя зависит от сигнатур ClamAV).

```json
{"md5":"900150983cd24fb0d6963f7d28e17f72","sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","size":3,"verdict":"clean","signature":"","duration_ms":1}
```

`GET /health` проверяет HTTP-процесс независимо от движка. `GET /ready` проверяет
ClamAV через `PING` и возвращает `503`, если движок недоступен.
`POST /scans` принимает ровно одну multipart-часть с именем `file`; дополнительные
части отклоняются. Имя файла и клиентский Content-Type не используются для решения
о безопасности. Пустые файлы отклоняются. `duration_ms` включает чтение файла,
вычисление хешей и ожидание результата движка.

Ошибки имеют единый формат:

```json
{"error":{"code":"file_too_large","message":"File or request body exceeds size limit"}}
```

Статусы: `400` — отсутствующий/пустой файл или повреждённый multipart,
`413` — превышение размера, `503` — заняты все слоты (`Retry-After: 1`),
`502` — ошибка движка/соединения, `504` — таймаут, `408` — отмена запроса
(клиент, уже закрывший соединение, ответ получить не сможет).
Неизвестные пути дают `404`, неверный HTTP-метод — `405`.
Ошибки ClamAV никогда не дают успешный результат `clean`.

## Настройки

| Переменная | По умолчанию | Значение |
|---|---|---|
| `SCANNER_HTTP_PORT` | `8082` | HTTP-порт; в Compose меняет порт на хосте |
| `THREAT_GRPC_ADDR` | пусто (каталог отключён) | gRPC target; в Compose `app_api:50051` |
| `CLAMAV_ADDRESS` | `localhost:3310` | TCP-адрес; в Compose задан `clamav:3310` |
| `SCANNER_MAX_FILE_BYTES` | `10485760` | Максимум файла, байты (10 MiB) |
| `SCANNER_MAX_CONCURRENT` | `4` | Одновременные проверки, 1–1024 |
| `SCANNER_SCAN_TIMEOUT` | `60s` | Весь запрос сканирования, включая загрузку |
| `CLAMAV_DIAL_TIMEOUT` | `3s` | Подключение к движку |
| `CLAMAV_TIMEOUT` | `60s` | Общий сетевой дедлайн одного обращения к движку |
| `SCANNER_SHUTDOWN_TIMEOUT` | `15s` | Ожидание активных запросов при остановке |
| `SCANNER_READ_HEADER_TIMEOUT` | `5s` | Чтение HTTP-заголовков |
| `SCANNER_IDLE_TIMEOUT` | `60s` | Простой keep-alive соединений |
| `SCANNER_STOP_GRACE_PERIOD` | `20s` | Только Compose: ожидание перед SIGKILL |

Таймауты задаются в формате Go duration (`500ms`, `30s`, `2m`), до 24 часов.
Для Compose значения можно экспортировать в окружение; для отдельного проекта
также можно передать `--env-file .env`. При увеличении shutdown timeout увеличьте и stop grace period, оставив запас.

HTTP body ограничен размером файла плюс 64 KiB на multipart-обрамление.
Размер самого файла проверяется отдельно. Очереди нет: при перегрузке нужно
повторить запрос позже. Буфер передачи в clamd — 32 KiB на запрос.
`clamav-init.sh` устанавливает `StreamMaxLength` и `MaxFileSize` из той же
`SCANNER_MAX_FILE_BYTES`. При запуске без Compose эти параметры clamd нужно
согласовать вручную. Для большого лимита учитывайте ограничения самого ClamAV.
`AlertExceedsMax yes` включает обнаружения `Heuristics.Limits.Exceeded` при
достижении внутренних лимитов (например, для архивов); они также дают `infected`.
`clean` означает отсутствие обнаружений в пределах возможностей и настроек движка.

Локальный запуск (нужен отдельно доступный clamd):

```sh
cd scanner
CLAMAV_ADDRESS=127.0.0.1:3310 go run ./cmd/scanner
```

Scanner пишет JSON-логи через `slog` в stdout, Docker собирает их как логи
контейнера. Смотреть: `docker compose logs -f scanner` или `make logs` из корня.
Есть запуск и остановка, HTTP method/path/status/duration, MD5, размер, verdict,
signature и статус каталога. Ошибки ClamAV пишутся на уровне ERROR; таймауты,
отмена, перегрузка и ошибки загрузки — WARN. Сбой каталога пишется отдельным WARN,
даже когда Scanner возвращает HTTP 200 с результатом ClamAV. Неуспешная проверка
`/ready` также содержит причину в логах. Содержимое, имена файлов и query-параметры
не логируются. При SIGINT/SIGTERM сервер закрывает
listener, ждёт активные запросы, затем при истечении дедлайна отменяет запросы
и принудительно закрывает соединения. Контексты запросов не отменяются сразу
по сигналу остановки.

## Тесты

```sh
cd scanner
go test -race ./...
go vet ./...
# После запуска Docker Compose и успешного /ready:
SCANNER_TEST_URL=http://127.0.0.1:8082 go test -tags=integration -v ./tests -count=1
```

Обычные тесты используют fake TCP-server и подмену движка, без Docker.
Проверяются framing INSTREAM, ответы и ошибки clamd, хеши, размеры,
отмена/таймауты, multipart, медленная загрузка, параллельность и оба сценария
завершения процесса через SIGTERM. Интеграционный тест отправляет чистый файл
и EICAR по HTTP в реальный сервис, проверяет вердикты, сигнатуры, размер и хеши.
Без доступного сервиса интеграционные тесты завершаются ошибкой, а не пропускаются.

Остановка отдельного проекта (без удаления сигнатур):

```sh
docker compose -f scanner/docker-compose.yml down
```

Нет авторизации, истории и базы результатов сканирования. HTTP публикуется
только на loopback. MD5 служит идентификатором содержимого, а не доказательством
его безопасности.

Протокол и особенности официального образа:
[ClamD Protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html),
[ClamAV Docker](https://docs.clamav.net/manual/Installing/Docker.html).

## Проверка каталога

Каталог использует одно gRPC-соединение на процесс, закрываемое после HTTP
shutdown. Каждый RPC ограничен 3 секундами и дедлайном исходного запроса.
Слот конкурентности занят только во время ClamAV. Статусы каталога: `found`,
`not_found`, `created`, `unavailable`, `error`; без каталога статус пустой.
Ошибка каталога отражается в `catalog_error`, успешный verdict ClamAV сохраняется.
Отмена исходного запроса прерывает всю операцию. При конкурентном создании
`AlreadyExists` приводит к одному повторному Get.

Из корня, после запуска сервисов:

```sh
THREAT_TEST_GRPC_ADDR=127.0.0.1:50051 go test -tags=integration -v ./scanner/tests -run '^TestRealThreatCatalog$' -count=1
go test -tags=integration -v ./scanner/tests -run '^TestRealClamAV$' -count=1
```

Первый тест отправляет уникальный чистый файл, проверяет `not_found`, создаёт
тестовую запись через gRPC и повторяет загрузку с ожиданием `found` и `clean`.
Он оставляет одну явно помеченную тестовую запись в PostgreSQL.
Проверка отказа каталога (Threat API восстанавливается и при ошибке теста):

```sh
(
  trap 'docker compose start app_api' EXIT
  docker compose stop app_api &&
  SCANNER_EXPECT_CATALOG_UNAVAILABLE=1 go test -tags=integration -v ./scanner/tests -run '^TestRealCatalogUnavailable$' -count=1
)
```
