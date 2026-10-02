FROM python:3.11-slim

# Run as a non-root user for defence in depth.
RUN useradd --create-home --uid 1000 botuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py scanner.py database.py config.py messages.py ./

# Directories for the SQLite DB and temp downloads.
RUN mkdir -p /app/data /tmp/telegram_virus_bot \
    && chown -R botuser:botuser /app /tmp/telegram_virus_bot

USER botuser

ENV PYTHONUNBUFFERED=1 \
    DB_PATH=/app/data/bot.db \
    TEMP_DIR=/tmp/telegram_virus_bot

CMD ["python", "bot.py"]
