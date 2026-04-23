# Proxy Admin Panel (Docker)

Админ-панель для управления прокси-пользователями с протоколами `HTTP` и `SOCKS5` в контейнерах Docker.

Текущий релиз: `1.0.1` (см. `CHANGELOG.md`).

## Что умеет

- создание/удаление/редактирование прокси-пользователей;
- включение/отключение доступа к `HTTP` и `SOCKS5` отдельно;
- live-счетчик трафика и количества запросов (входящий/исходящий/общий, обновляется каждые 2 секунды);
- backup полной SQLite БД панели (`.db`, пользователи, трафик, сэмплы, события лога и т.д.);
- восстановление из файла `.db` или из legacy JSON (только пользователи);
- при восстановлении из бэкапа сохраняются MTProto-секреты (ссылки `tg://proxy` не пересоздаются);
- авторизация в админ-панель (сессионная cookie);
- копирование `tg://socks...` ссылки для Telegram по кнопке у пользователя;
- MTProto прокси с индивидуальным секретом на пользователя;
- вкладка графиков утилизации трафика с фильтром по пользователю.

## Быстрый старт

```bash
docker compose up --build -d
```

Панель: [http://localhost:8000](http://localhost:8000)

Каталог данных на **хосте** (bind mount в контейнер как `/data`):

- Переменная **`PANEL_DATA_HOST_PATH`** в `.env` (см. `docker-compose.yml`). По умолчанию для локального запуска: `./data` относительно каталога с compose-файлом.
- В контейнере: `DATABASE_URL=sqlite:////data/panel.db`, бэкапы из панели: `/data/backups/*.db`.
- На сервере после `deploy/install.sh` каталог создаётся автоматически: **`${INSTALL_DIR}/data`** (обычно `/opt/proxy-admin-panel/data`) и прописывается в `.env`.
- Резервное копирование без Docker: скопируйте **`panel.db`** (и при необходимости `backups/`) с этого пути.

Переход со **старого именованного тома** `panel_data` на bind mount (один раз): узнайте имя тома (`docker volume ls`), затем:

```bash
mkdir -p ./data
docker run --rm -v ИМЯ_ТОМА_panel_data:/from -v "$(pwd)/data:/to" alpine sh -c 'cp -a /from/. /to/'
# в .env: PANEL_DATA_HOST_PATH=/абсолютный/путь/к/data
docker compose up -d
```

Дефолтный вход:

- логин: `admin`
- пароль: `admin123`

## Установка на пустую машину (через GitHub)

Скрипт `deploy/install.sh` устанавливает Docker/Compose, клонирует проект, спрашивает параметры и поднимает панель.

### Что скрипт спросит

- порт панели;
- порты HTTP/SOCKS5 прокси;
- пароль админа.
- домен панели для публичных ссылок/MTProto (обязательно для `faketls`).

Остальные параметры скрипт выставляет автоматически:

- логин админа: `admin`;
- `PROXY_PUBLIC_HOST=auto`;
- принимает любые пароли админа (включая спецсимволы), кроме переводов строки.

### Запуск

1) Скачайте репозиторий/скрипт на целевую машину.  
2) Запустите:

```bash
sudo bash deploy/install.sh
```

Если хотите запуск прямо из raw GitHub, можно так (замените URL):

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/deploy/install.sh | sudo bash
```

### Важно

- установщик делает self-check логина и показывает результат;
- используйте пароль админа только из финального вывода установщика или из `${INSTALL_DIR}/.env`.
- перед запуском Docker установщик проверяет, что ключевые порты свободны (`panel/http/socks/mtproto`);
- установщик автоматически пытается открыть firewall порты (`panel/http/socks/mtproto`);
- для MTProto в `.env` автоматически выставляется `MTPROTO_PUBLIC_HOST` и `MTPROTO_FAKE_TLS_DOMAIN` как DNS панели (если домен задан), иначе fallback;
- для `MTPROTO_SECRET_MODE=faketls` установщик требует указать домен панели (иначе останавливается с ошибкой);
- если домен панели задан, установщик проверяет, что DNS A-запись домена указывает на внешний IP сервера, и останавливается при mismatch (чтобы избежать MTProto "недоступен").

Прокси порты на хосте:

- HTTP: `13128` (в контейнере `3128`)
- SOCKS5: `11080` (в контейнере `1080`)
- MTProto: `2053` (в контейнере `3443`)

Для Telegram ссылки (`tg://socks`) используется:

- `PROXY_PUBLIC_HOST` (по умолчанию `auto`, берется хост запроса);
- `SOCKS_PROXY_PORT` (по умолчанию `11080`).

Для HTTP URL в модальном окне используется:
- `MTPROTO_PUBLIC_PORT` (по умолчанию `2053`) для `tg://proxy?...` ссылок;
- `MTPROTO_PUBLIC_HOST` (опционально) — отдельный хост для MTProto ссылки.
  Это полезно, если панель идет через Cloudflare proxy, а MTProto нужен через `DNS only` хост.
  Если не задан, панель пытается автоматически подставить внешний IP сервера.
- `MTPROTO_SECRET_MODE`:
  - `faketls` (по умолчанию, `ee` + 32 hex + hex-домен из `MTPROTO_FAKE_TLS_DOMAIN`),
  - `classic` (`dd` + 32 hex).

- `PROXY_PUBLIC_HOST`;
- `HTTP_PROXY_PORT` (по умолчанию `13128`).

Параметры минимальной нагрузки:

- `PROXY_LOGDUMP_BYTES` (по умолчанию `65536`) — как часто `3proxy` пишет промежуточные записи при длинных сессиях. Больше значение = меньше нагрузка, реже обновления.
- `TRAFFIC_POLL_INTERVAL_SECONDS` (по умолчанию `2.0`) — как часто backend читает лог и обновляет БД.

## Обновление с GitHub

Повторный запуск `sudo bash deploy/install.sh` обновляет репозиторий (в т.ч. shallow clone), записывает в `.env` тег образа `PANEL_IMAGE_TAG` по текущему коммиту и поднимает стек с `--build`, чтобы Docker не оставался на старом слое.

Вручную после `git pull` в каталоге установки:

```bash
export PANEL_IMAGE_TAG="$(git rev-parse --short HEAD)"
export PANEL_GIT_REVISION="$(git rev-parse HEAD)"
docker compose --env-file .env up -d --build
```

Проверка, что поднялась нужная ревизия: `curl -sS http://127.0.0.1:8000/health` — в JSON будет поле `revision` (полный SHA коммита, зашитый при сборке образа).

## Проверка здоровья

```bash
curl -fsS http://localhost:8000/health
```

## API

- `GET /api/users` - список пользователей (пагинация: `page`, `per_page`, опционально `q`)
- `GET /api/traffic/samples` - данные для графиков (все/по пользователю)
- `POST /api/auth/login` - вход в панель
- `POST /api/auth/logout` - выход из панели
- `GET /api/auth/me` - проверка сессии
- `GET /api/meta` - host/port для Telegram SOCKS ссылки
- `POST /api/users` - создать пользователя
- `PUT /api/users/{id}` - обновить пользователя
- `DELETE /api/users/{id}` - удалить пользователя
- `POST /api/backup` - выгрузить снимок SQLite (`.db`)
- `POST /api/restore` - восстановить из `.db` или legacy JSON

## Примечание по безопасности

Пароли пользователей в этой реализации хранятся в базе в открытом виде, потому что `3proxy` использует их для авторизации и требуется точный backup/restore "1-в-1". Для production рекомендуется:

- ограничить сетевой доступ к панели;
- использовать reverse proxy + TLS + auth;
- шифровать volume/backup на уровне инфраструктуры.
