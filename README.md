# Stoatmod

Stoatmod is a moderation bot for [Stoat](https://stoat.chat) servers. This repository contains
the bot and the dashboard API that the [Stoatmod website](https://github.com/StoatMod-site/StoatMod-dashboard)
talks to. The hosted service runs at [modstoat.site](https://modstoat.site).

## What's included

- **The bot** (`bot.py` and the modules next to it): AI content and image moderation, spam and
  mass-mention protection, warnings and cases, appeals, applications, reaction roles, polls,
  automations, join CAPTCHA and anonymous server statistics.
- **The dashboard API** (`api/`): the aiohttp service behind the server dashboard, appeals,
  reports and the public website data. It shares the bot's SQLite database.
- **Tests** (`tests/`) for both.

Not included: Stoatmod's internal staff tools, private infrastructure, and any training data.
The moderation model itself will be published separately.

## Requirements

- Python 3.12+
- A Stoat bot token
- An AI moderation endpoint compatible with Stoatmod's StoatGuard API (`/health`, `/classify`,
  `/classify-image`). Moderation is fail-open: if the model is unreachable, messages are left alone.

## Setup

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env          # bot settings
cp api/.env.example api/.env  # dashboard API settings
```

Fill in `STOAT_BOT_TOKEN`, `LOCAL_AI_BASE_URL`, `LOCAL_AI_EXPECTED_VERSION` and
`GLOBAL_COMMAND_OWNER_ID` (your Stoat user ID) in `.env`. The expected version must exactly match
the `version` returned by the model's `/health` endpoint. Model weights and a model server are
not included in this release; an existing compatible endpoint is required.

Then start the bot and API from the repository root, in separate terminals:

```bash
.venv/bin/python bot.py           # the bot
.venv/bin/python api/server.py    # the dashboard API
```

Example systemd units are in `deploy/`. Serve the website and `/api/` through one origin.
`deploy/stoatmod-watchdog.timer` runs `ops/stoatmod_watchdog.py` every minute: it checks the bot heartbeat, the AI
endpoint, the services and disk space, restarts an AI tunnel if you use one, and can post uptime alerts to a Stoat
webhook. Copy `ops/watchdog.env.example` to `/opt/stoatmod/ops/watchdog.env` to configure it.
For an HTTPS deployment, set `DASHBOARD_ALLOWED_ORIGIN` to that public origin and
`DASHBOARD_SECURE_COOKIES=true` in `api/.env`; the example defaults are for local development.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -t .
```

## Privacy

Stoatmod keeps only what each feature needs and deletes time-limited data automatically. See the
[privacy policy](https://modstoat.site/privacy) and [what changed in October 2026](https://modstoat.site/privacy-changes).
If you run your own copy, you're responsible for your own users' data and for following Stoat's
rules for bots.

## License

Copyright (C) 2026 Stoatmod Limited

Licensed under the [GNU Affero General Public License v3.0](LICENSE). If you run a modified
version as a service for others, you must make your modified source code available to its users.
