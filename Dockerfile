# Используем официальный образ Python
FROM python:3.9-slim

# Метаданные
LABEL org.opencontainers.image.source="https://github.com/ваш-репозиторий/proteya"

# Указываем, что в продакшене
ARG ENV=prod
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on

# Создаём пользователя
RUN adduser --disabled-password --gecos '' appuser

# Рабочая директория
WORKDIR /app

# Копируем зависимости и устанавливаем
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    rm -rf /root/.cache/pip

# Копируем Angular-фронтенд
COPY frontend_dist /angular/dist/proteya_notes/browser

# Копируем основные файлы
COPY backend.py auth.py voice_backend.py database.py ./
COPY static static/

# --- Критически: создаём папки для файлов и даём права appuser ---
RUN mkdir -p static/files static/workspaces/avatars && \
    chown -R appuser:appuser static && \
    chmod -R 755 static



# Папка для БД
RUN mkdir -p /data && chown -R appuser:appuser /data
VOLUME ["/data"]

# Переключаемся на непривилегированного пользователя
USER appuser

# Порт
EXPOSE 8000

# Запуск с проверкой на наличие сертификатов
CMD ["sh", "-c", "if [ -f cert.pem ] && [ -f privkey.pem ]; then echo '🔐 Запуск с HTTPS'; exec uvicorn backend:app --host 0.0.0.0 --port 8000 --ssl-certfile cert.pem --ssl-keyfile privkey.pem; else echo '🔓 Запуск без HTTPS'; exec uvicorn backend:app --host 0.0.0.0 --port 8000; fi"]