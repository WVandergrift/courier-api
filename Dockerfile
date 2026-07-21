FROM python:3.12-slim

ARG COURIER_REVISION=unknown
ENV COURIER_REVISION=$COURIER_REVISION
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin courier

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data && chown -R courier:courier /data /app
USER courier

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
