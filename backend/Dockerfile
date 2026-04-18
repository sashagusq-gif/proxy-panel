FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app/app
COPY templates /app/templates
COPY static /app/static

# Меняется при каждом деплое с новым коммитом — срывает кэш слоёв Docker после COPY.
ARG PANEL_GIT_REVISION=unknown
RUN printf '%s\n' "${PANEL_GIT_REVISION}" > /app/.git-revision

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
