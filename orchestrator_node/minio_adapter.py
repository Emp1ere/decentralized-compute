"""
Адаптер MinIO (S3-совместимое хранилище) для DSCM v2.

ТЗ раздел 2, ADR 002. Замена IPFS/локального хранилища.
"""
from __future__ import annotations

import os
from typing import Optional, Tuple

MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "")
MINIO_BUCKET_INGESTION = os.environ.get("MINIO_BUCKET_INGESTION", "dscm-ingestion")
MINIO_BUCKET_RESULTS = os.environ.get("MINIO_BUCKET_RESULTS", "dscm-results")
MINIO_SECURE = os.environ.get("MINIO_SECURE", "true").lower() in ("1", "true", "yes")


def is_configured() -> bool:
    """Проверка, настроен ли MinIO."""
    return bool(MINIO_ACCESS_KEY and MINIO_SECRET_KEY)


def upload_ingestion(
    object_key: str, data: bytes, content_type: str = "application/octet-stream"
) -> Tuple[bool, Optional[str]]:
    """
    Загрузка входных данных в бакет ingestion.

    Returns:
        (success, error_message)
    """
    if not is_configured():
        return False, "MinIO not configured"
    try:
        from minio import Minio
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        from io import BytesIO
        client.put_object(
            MINIO_BUCKET_INGESTION,
            object_key,
            BytesIO(data),
            len(data),
            content_type=content_type,
        )
        return True, None
    except ImportError:
        return False, "minio package not installed (pip install minio)"
    except Exception as e:
        return False, str(e)


def download_ingestion(object_key: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Скачивание из бакета ingestion. Returns (data, error_message)."""
    if not is_configured():
        return None, "MinIO not configured"
    try:
        from minio import Minio
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        response = client.get_object(MINIO_BUCKET_INGESTION, object_key)
        data = response.read()
        response.close()
        response.release_conn()
        return data, None
    except ImportError:
        return None, "minio package not installed"
    except Exception as e:
        return None, str(e)


def download_result(object_key: str) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Скачивание результата из бакета results.

    Returns:
        (data, error_message)
    """
    if not is_configured():
        return None, "MinIO not configured"
    try:
        from minio import Minio
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        response = client.get_object(MINIO_BUCKET_RESULTS, object_key)
        data = response.read()
        response.close()
        response.release_conn()
        return data, None
    except ImportError:
        return None, "minio package not installed"
    except Exception as e:
        return None, str(e)


def get_presigned_upload_url(object_key: str, expires_seconds: int = 3600) -> Optional[str]:
    """Presigned URL для загрузки в ingestion (клиент загружает напрямую)."""
    if not is_configured():
        return None
    try:
        from minio import Minio
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        return client.presigned_put_object(
            MINIO_BUCKET_INGESTION, object_key, expires=expires_seconds
        )
    except (ImportError, Exception):
        return None


def get_presigned_download_url(
    object_key: str, bucket: str = MINIO_BUCKET_INGESTION, expires_seconds: int = 3600
) -> Optional[str]:
    """Presigned URL для скачивания (воркер загружает входные данные)."""
    if not is_configured():
        return None
    try:
        from minio import Minio
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        return client.presigned_get_object(bucket, object_key, expires=expires_seconds)
    except (ImportError, Exception):
        return None


def upload_result(
    object_key: str, data: bytes, content_type: str = "application/octet-stream"
) -> Tuple[bool, Optional[str]]:
    """Загрузка результата в бакет results. Returns (success, error_message)."""
    if not is_configured():
        return False, "MinIO not configured"
    try:
        from minio import Minio
        from io import BytesIO
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        client.put_object(
            MINIO_BUCKET_RESULTS,
            object_key,
            BytesIO(data),
            len(data),
            content_type=content_type,
        )
        return True, None
    except ImportError:
        return False, "minio package not installed"
    except Exception as e:
        return False, str(e)


def get_presigned_upload_url_results(object_key: str, expires_seconds: int = 3600) -> Optional[str]:
    """Presigned URL для загрузки результата воркером."""
    if not is_configured():
        return None
    try:
        from minio import Minio
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        return client.presigned_put_object(
            MINIO_BUCKET_RESULTS, object_key, expires=expires_seconds
        )
    except (ImportError, Exception):
        return None
