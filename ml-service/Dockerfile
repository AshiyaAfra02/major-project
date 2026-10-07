# Python version matched to the project venv (3.10.11)
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 `
    PYTHONUNBUFFERED=1

RUN apt-get update `
    && apt-get install -y --no-install-recommends libgomp1 `
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 user

USER user

ENV HOME=/home/user `
    PATH=/home/user/.local/bin:$PATH

WORKDIR /home/user/app

COPY --chown=user requirements.txt .

RUN pip install --no-cache-dir --upgrade pip `
    && pip install --no-cache-dir -r requirements.txt

COPY --chown=user . .

EXPOSE 7860

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860"]
