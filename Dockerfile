FROM python:3.12-slim

WORKDIR /app

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and configuration data
COPY backend ./backend
COPY data ./data
COPY alembic.ini ./

# Install project package
RUN pip install --no-cache-dir -e .

ENV PORT=8000
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["sh", "-c", "uvicorn sih26155.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
