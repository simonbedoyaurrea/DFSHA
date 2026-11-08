"""Lectura de configuración desde variables de entorno (o NOMBRE_FILE para secretos)."""
import os


def get(name, default=None):
    return os.environ.get(name, default)


def geti(name, default):
    return int(os.environ.get(name, default))


def getf(name, default):
    return float(os.environ.get(name, default))


def getb(name, default=False):
    return os.environ.get(name, "1" if default else "0").lower() in ("1", "true", "yes")


def getl(name, default=""):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


def secret(name, default=None):
    """Devuelve NAME, o el contenido del archivo NAME_FILE."""
    v = os.environ.get(name)
    if v:
        return v
    f = os.environ.get(name + "_FILE")
    if f and os.path.exists(f):
        return open(f).read().strip()
    return default
