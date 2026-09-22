"""Collect EC2 and ALB CloudWatch metrics and persist raw points to MySQL."""

import json
import math
import os
from datetime import datetime, timedelta, timezone

import boto3
import pymysql


REGION = os.environ.get("AWS_REGION", "ap-northeast-2")
INSTANCE_ID = os.environ["MONITORED_INSTANCE_ID"]
ALB_DIMENSION = os.environ["MONITORED_ALB_DIMENSION"]
TARGET_GROUP_DIMENSION = os.environ["MONITORED_TARGET_GROUP_DIMENSION"]
DB_SECRET_ID = os.environ["DB_SECRET_ID"]
PERIOD_SECONDS = int(os.environ.get("METRIC_PERIOD_SECONDS", "60"))

cloudwatch = boto3.client("cloudwatch", region_name=REGION)
secretsmanager = boto3.client("secretsmanager", region_name=REGION)


METRICS = {
    "cpu": {
        "service": "EC2",
        "resource_id": INSTANCE_ID,
        "metric_name": "CPUUtilization",
        "namespace": "AWS/EC2",
        "dimensions": [{"Name": "InstanceId", "Value": INSTANCE_ID}],
        "stat": "Average",
        "unit": "Percent",
    },
    "memory": {
        "service": "EC2",
        "resource_id": INSTANCE_ID,
        "metric_name": "mem_used_percent",
        "namespace": "CWAgent",
        "dimensions": [{"Name": "InstanceId", "Value": INSTANCE_ID}],
        "stat": "Average",
        "unit": "Percent",
    },
    "status_check": {
        "service": "EC2",
        "resource_id": INSTANCE_ID,
        "metric_name": "StatusCheckFailed",
        "namespace": "AWS/EC2",
        "dimensions": [{"Name": "InstanceId", "Value": INSTANCE_ID}],
        "stat": "Maximum",
        "unit": "Count",
    },
    "latency": {
        "service": "ALB",
        "resource_id": ALB_DIMENSION,
        "metric_name": "TargetResponseTime",
        "namespace": "AWS/ApplicationELB",
        "dimensions": [{"Name": "LoadBalancer", "Value": ALB_DIMENSION}],
        "stat": "Average",
        "unit": "Seconds",
    },
    "request_count": {
        "service": "ALB",
        "resource_id": ALB_DIMENSION,
        "metric_name": "RequestCount",
        "namespace": "AWS/ApplicationELB",
        "dimensions": [{"Name": "LoadBalancer", "Value": ALB_DIMENSION}],
        "stat": "Sum",
        "unit": "Count",
    },
    "target_5xx": {
        "service": "ALB",
        "resource_id": ALB_DIMENSION,
        "metric_name": "HTTPCode_Target_5XX_Count",
        "namespace": "AWS/ApplicationELB",
        "dimensions": [{"Name": "LoadBalancer", "Value": ALB_DIMENSION}],
        "stat": "Sum",
        "unit": "Count",
    },
    "elb_5xx": {
        "service": "ALB",
        "resource_id": ALB_DIMENSION,
        "metric_name": "HTTPCode_ELB_5XX_Count",
        "namespace": "AWS/ApplicationELB",
        "dimensions": [{"Name": "LoadBalancer", "Value": ALB_DIMENSION}],
        "stat": "Sum",
        "unit": "Count",
    },
    "healthy_hosts": {
        "service": "ALB",
        "resource_id": TARGET_GROUP_DIMENSION,
        "metric_name": "HealthyHostCount",
        "namespace": "AWS/ApplicationELB",
        "dimensions": [
            {"Name": "LoadBalancer", "Value": ALB_DIMENSION},
            {"Name": "TargetGroup", "Value": TARGET_GROUP_DIMENSION},
        ],
        "stat": "Minimum",
        "unit": "Count",
    },
    "unhealthy_hosts": {
        "service": "ALB",
        "resource_id": TARGET_GROUP_DIMENSION,
        "metric_name": "UnHealthyHostCount",
        "namespace": "AWS/ApplicationELB",
        "dimensions": [
            {"Name": "LoadBalancer", "Value": ALB_DIMENSION},
            {"Name": "TargetGroup", "Value": TARGET_GROUP_DIMENSION},
        ],
        "stat": "Maximum",
        "unit": "Count",
    },
}


def _metric_queries():
    return [
        {
            "Id": query_id,
            "ReturnData": True,
            "MetricStat": {
                "Metric": {
                    "Namespace": spec["namespace"],
                    "MetricName": spec["metric_name"],
                    "Dimensions": spec["dimensions"],
                },
                "Period": PERIOD_SECONDS,
                "Stat": spec["stat"],
            },
        }
        for query_id, spec in METRICS.items()
    ]


def _db_config():
    response = secretsmanager.get_secret_value(SecretId=DB_SECRET_ID)
    secret = json.loads(response["SecretString"])
    return {
        "host": secret["host"],
        "port": int(secret.get("port", 3306)),
        "user": secret["username"],
        "password": secret["password"],
        "database": secret.get("database", "security"),
    }


def _rows_from_response(response):
    rows = []
    for result in response.get("MetricDataResults", []):
        if result.get("StatusCode") not in (None, "Complete"):
            raise RuntimeError(
                f"CloudWatch returned {result.get('StatusCode')} for {result['Id']}"
            )
        spec = METRICS[result["Id"]]
        for timestamp, value in zip(result.get("Timestamps", []), result.get("Values", [])):
            if not math.isfinite(value):
                continue
            collected_at = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
            rows.append(
                (
                    spec["service"],
                    spec["resource_id"],
                    spec["metric_name"],
                    value,
                    spec["unit"],
                    PERIOD_SECONDS,
                    collected_at,
                )
            )
    return rows


def _write_rows(rows):
    if not rows:
        return 0

    connection = pymysql.connect(
        **_db_config(),
        charset="utf8mb4",
        connect_timeout=5,
        read_timeout=10,
        write_timeout=10,
        autocommit=False,
    )
    try:
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO monitoring_metrics (
                    service, resource_id, metric_name, metric_value,
                    unit, period_seconds, collected_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    metric_value = VALUES(metric_value),
                    unit = VALUES(unit),
                    period_seconds = VALUES(period_seconds)
                """,
                rows,
            )
        connection.commit()
    finally:
        connection.close()
    return len(rows)


def lambda_handler(event, context):
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(seconds=max(PERIOD_SECONDS * 3, 300))
    response = cloudwatch.get_metric_data(
        MetricDataQueries=_metric_queries(),
        StartTime=start_time,
        EndTime=end_time,
        ScanBy="TimestampAscending",
    )
    rows = _rows_from_response(response)
    written = _write_rows(rows)
    return {"queriedMetrics": len(METRICS), "writtenPoints": written}
