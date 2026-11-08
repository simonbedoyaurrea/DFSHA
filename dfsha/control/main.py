import logging
import threading

import uvicorn

from ..common import config as C
from ..common import tls


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    from .app import internal, pub
    host = C.get("HOST", "0.0.0.0")
    # puerto interno (nodos de datos -> control): exige certificado de cliente (mTLS)
    cfg = uvicorn.Config(internal, host=host, port=C.geti("INTERNAL_PORT", 8100), log_level="warning",
                         **tls.uvicorn_kwargs(require_client_cert=True))
    threading.Thread(target=uvicorn.Server(cfg).run, daemon=True).start()
    # puerto público (clientes): TLS normal
    uvicorn.run(pub, host=host, port=C.geti("PORT", 8000), log_level="info",
                **tls.uvicorn_kwargs(require_client_cert=False))


if __name__ == "__main__":
    main()
