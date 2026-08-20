"""
WebSocket Router para AuditShield.
Maneja conexiones WebSocket para transmitir logs y estado del escaneo en tiempo real.
Usa Redis Pub/Sub para conectar las tareas de Celery con los clientes FastAPI.
Si Redis no está disponible, hace polling a la base de datos.
"""

import asyncio
import logging
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

# Intentar conectar a Redis (opcional)
_redis_available = False
try:
    import redis as redis_lib
    _test = redis_lib.from_url(settings.REDIS_URL)
    _test.ping()
    _redis_available = True
except Exception:
    logger.warning("Redis no disponible para WebSocket — se usará polling en modo dev.")


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)


manager = ConnectionManager()


@router.websocket("/audit/{audit_id}")
async def websocket_audit_logs(websocket: WebSocket, audit_id: int):
    """
    WebSocket que transmite logs de ejecución y progreso al frontend.
    Con Redis: usa Pub/Sub para tiempo real.
    Sin Redis: hace polling a la DB cada segundo.
    """
    await manager.connect(websocket)

    try:
        await websocket.send_json({
            "type": "log",
            "message": "Conectado al canal de auditoría en vivo.",
            "progress": 0
        })

        if _redis_available:
            # Modo Redis Pub/Sub (producción)
            import redis as redis_lib
            r_client = redis_lib.from_url(settings.REDIS_URL)
            pubsub = r_client.pubsub()
            channel = f"audit_channel_{audit_id}"

            try:
                pubsub.subscribe(channel)
                loop = asyncio.get_event_loop()

                while True:
                    msg = await loop.run_in_executor(None, pubsub.get_message, True, 0.5)
                    if msg and msg["type"] == "message":
                        data_str = msg["data"].decode("utf-8")
                        data_json = json.loads(data_str)
                        await websocket.send_json(data_json)
                        if data_json.get("type") in ["complete", "error"]:
                            break
                    await asyncio.sleep(0.1)
            finally:
                pubsub.unsubscribe(channel)
                pubsub.close()
        else:
            # Modo Polling a DB (desarrollo local sin Redis)
            from app.core.database import AsyncSessionLocal
            from app.models.audit import Audit, AuditStatus

            last_progress = -1
            while True:
                async with AsyncSessionLocal() as db:
                    audit = await db.get(Audit, audit_id)
                    if audit:
                        progress = audit.progress
                        status = audit.status

                        if progress != last_progress:
                            last_progress = progress
                            await websocket.send_json({
                                "type": "progress",
                                "audit_id": audit_id,
                                "message": f"Módulo: {audit.current_module or 'Procesando...'}",
                                "progress": progress,
                                "data": {}
                            })

                        if status in [AuditStatus.COMPLETED.value, AuditStatus.FAILED.value, AuditStatus.CANCELLED.value]:
                            await websocket.send_json({
                                "type": "complete" if status == AuditStatus.COMPLETED.value else "error",
                                "audit_id": audit_id,
                                "message": f"Auditoría {status}",
                                "progress": 100,
                                "data": {
                                    "score": audit.security_score,
                                    "letter": audit.score_letter,
                                    "summary": audit.summary
                                }
                            })
                            break
                await asyncio.sleep(1)

    except WebSocketDisconnect:
        logger.info(f"Cliente desconectado del WebSocket para auditoría {audit_id}")
    except Exception as e:
        logger.error(f"Error en WebSocket para auditoría {audit_id}: {e}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": f"Error de conexión: {str(e)}",
                "progress": 100
            })
        except Exception:
            pass
    finally:
        manager.disconnect(websocket)

