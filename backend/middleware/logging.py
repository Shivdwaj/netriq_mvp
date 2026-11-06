import time
import uuid
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from backend.utils.logger import get_logger

logger = get_logger(__name__)

class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Logs every incoming request and outgoing response status.
    Injects and tracks X-Request-ID header across requests and responses.
    """
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        request_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
        request.state.request_id = request_id
        
        # Log request
        logger.info(f"API Request [{request_id}]: {request.method} {request.url.path} from {client_ip}")
        
        # Process request
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            process_time = time.time() - start_time
            logger.info(f"API Response [{request_id}]: {response.status_code} [{process_time:.4f}s]")
            return response
        except Exception as e:
            process_time = time.time() - start_time
            logger.error(f"API Unhandled Exception [{request_id}]: {str(e)} [{process_time:.4f}s]")
            raise
