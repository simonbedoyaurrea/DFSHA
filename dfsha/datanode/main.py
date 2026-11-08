import logging
import threading

import uvicorn

from ..common import config as C
from ..common import tls


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    from .app import Agent, internal, pub, scrub_loop
    host = C.get("HOST", "0.0.0.0")
    cfg = uvicorn.Config(internal, host=host, port=C.geti("INTERNAL_PORT", 9101), log_level="warning",
                         **tls.uvicorn_kwargs(require_client_cert=True))
    threading.Thread(target=uvicorn.Server(cfg).run, daemon=True).start()
    Agent().start()
    threading.Thread(target=scrub_loop, daemon=True).start()
    uvicorn.run(pub, host=host, port=C.geti("PORT", 9001), log_level="warning",
                **tls.uvicorn_kwargs(require_client_cert=False))


if __name__ == "__main__":
    main()
