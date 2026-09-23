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
# fonts-nanum: AI 진단 PDF 보고서에 한글을 쓰기 위한 폰트(reportlab은 기본
# 내장 폰트에 한글 글리프가 없어서, 실제 폰트 파일을 임베드해야 함).
RUN apt-get update && apt-get install -y --no-install-recommends \
  default-mysql-client fonts-nanum \
  && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY --from=frontend /app/dist ./static

EXPOSE 8443
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:8443", "--workers", "2", "--timeout", "60", "app:app"]
