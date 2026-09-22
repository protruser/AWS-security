# 1단계: 프론트엔드 빌드
FROM node:22-slim AS frontend
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html vite.config.ts tsconfig.json ./
COPY src ./src
RUN npm run build

# 2단계: Flask가 위 빌드 결과(dist)를 static/ 로 받아 함께 서빙
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends default-mysql-client \
  && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY --from=frontend /app/dist ./static

EXPOSE 8443
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:8443", "--workers", "2", "--timeout", "60", "app:app"]
