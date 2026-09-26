import json
import os
from functools import lru_cache

import pymysql
from dotenv import load_dotenv

load_dotenv()


@lru_cache(maxsize=1)
def _load_db_config() -> dict:
    """DB 접속정보를 환경변수 또는 Secrets Manager에서 읽는다.

    - 로컬: DB_HOST/DB_USER/DB_PASSWORD/DB_NAME 사용
    - 운영 Dashboard EC2: DB_SECRET_ID를 설정하면 IAM Role로 Secret 조회
    """
    secret_id = os.getenv("DB_SECRET_ID", "").strip()

    if secret_id:
        import boto3

        region = os.getenv("AWS_REGION", "ap-northeast-2")
        client = boto3.client("secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=secret_id)
        secret = json.loads(response["SecretString"])

        return {
            "host": secret["host"],
            "port": int(secret.get("port", 3306)),
            "user": secret["username"],
            "password": secret["password"],
            "database": secret.get("database", "security"),
        }

    required = ["DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME"]
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise RuntimeError(
            "DB 접속 환경변수가 없습니다: " + ", ".join(missing)
        )

    return {
        "host": os.environ["DB_HOST"],
        "port": int(os.getenv("DB_PORT", "3306")),
        "user": os.environ["DB_USER"],
        "password": os.environ["DB_PASSWORD"],
        "database": os.environ["DB_NAME"],
    }


def get_connection():
    config = _load_db_config()
    return pymysql.connect(
        host=config["host"],
        port=config["port"],
        user=config["user"],
        password=config["password"],
        database=config["database"],
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        connect_timeout=5,
        read_timeout=10,
        write_timeout=10,
    )
