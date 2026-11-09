"""Regresiones de publicación: usa los endpoints reales de los nodos, sin etcd externo.

    python -m pytest tests/test_commit_safety.py -q

Estas pruebas no sustituyen los ensayos distribuidos con etcd y AWS.
"""
import base64
import hashlib
import importlib
import json
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(scope="module")
def modules(tmp_path_factory):
    root = tmp_path_factory.mktemp("keys")
    key = Ed25519PrivateKey.generate()
    private = root / "private.pem"
    public = root / "public.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.MonkeyPatch.context() as mp:
        for name, value in {"PRIVATE_KEY": str(private), "PUBLIC_KEY": str(public),
                            "KEK": base64.b64encode(bytes(32)).decode(),
                            "CLUSTER_TOKEN": "test-cluster-token", "TLS": "0",
                            "DATA_DIR": str(root / "data"), "W": "2", "RF": "3"}.items():
            mp.setenv(name, value)
        control = importlib.import_module("dfsha.control.app")
        data = importlib.import_module("dfsha.datanode.app")
    return control, data


class Metadata:
    """Catálogo mínimo para probar validaciones antes de la publicación."""
    def __init__(self, E, manifest, lock_id, plans):
        self.E = E
        self.values = {
            "/files/f1": manifest,
            f"/locks/f1/{lock_id}": {"uid": "alice", "mode": "w", "ranges": [[0, None]]},
            **{f"/pending/{bid}": plan for bid, plan in plans.items()},
        }
        self.publications = 0

    def get(self, key):
        value = self.values.get(key)
        return self.E.KV(key, json.dumps(value), 7, 7, 1, 1) if value is not None else None

    def txn(self, compares, success, failure=None):
        for op in success:
            if "request_put" in op:
                entry = op["request_put"]
                key = self.E.b64d(entry["key"])
                self.values[key] = json.loads(self.E.b64d(entry["value"]))
                if key == "/files/f1":
                    self.publications += 1
            else:
                self.values.pop(self.E.b64d(op["request_delete_range"]["key"]), None)
        return True, 8, []


@pytest.fixture
def cluster(modules, monkeypatch, tmp_path):
    control, data = modules
    from dfsha.datanode.store import Store

    stores = {name: Store(str(tmp_path / name)) for name in ("dn1", "dn2", "dn3")}
    server = TestClient(data.internal)
    encrypted = b"x" * (8 + 28)  # tamaño de contenido + nonce y etiqueta AES-GCM
    bid = "f1-0-1-test"
    sha = hashlib.sha256(encrypted).hexdigest()
    for store in stores.values():
        store.write(bid, 1, encrypted, sha)
    plan = {"fid": "f1", "uid": "alice", "index": 0, "gen": 1,
            "lock_id": "f1.lock", "nodes": [
                {"id": name, "internal_url": f"http://{name}"} for name in stores]}
    m = {"fid": "f1", "uid": "alice", "path": "/test.bin", "state": "PENDING",
         "version": 0, "block_size": 8, "blocks": [], "size": 0}
    db = Metadata(control.E, m, "f1.lock", {bid: plan})
    monkeypatch.setattr(control, "etcd", db)
    dead = set()

    def route(request):
        node = request.url.host
        if node in dead:
            return httpx.Response(503, json={"detail": "node unavailable"})
        # Simula el transporte; cada solicitud entra al endpoint real de un nodo.
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(data, "NODE_ID", node)
            mp.setattr(data, "store", stores[node])
            response = server.get(request.url.raw_path.decode(), headers=dict(request.headers))
        return httpx.Response(response.status_code, json=response.json())

    monkeypatch.setattr(control.tls, "http_client", lambda **kw: httpx.Client(
        transport=httpx.MockTransport(route)))
    # En este transporte de prueba, las instancias del nodo comparten un módulo.
    # Serializar sus solicitudes evita mezclar el Store de cada instancia.
    import threading
    mu = threading.Lock()
    original = route

    def serial_route(request):
        with mu:
            return original(request)

    monkeypatch.setattr(control.tls, "http_client", lambda **kw: httpx.Client(
        transport=httpx.MockTransport(serial_route)))

    change = {"index": 0, "block_id": bid, "gen": 1, "size": 8,
              "sha256": sha, "acked": ["inventado1", "inventado2"]}
    body = control.CommitBody(lock_id="f1.lock", fencing_token=7, base_version=0,
                              changes=[change], size=8, replace_all=True)
    return control, data, db, stores, dead, body


def test_publish_with_two_real_copies_and_one_unavailable(cluster):
    control, _, db, _, dead, body = cluster
    dead.add("dn3")
    result = control.commit("f1", body, {"sub": "alice"})
    assert result["version"] == 1
    assert db.publications == 1
    assert set(db.values["/files/f1"]["blocks"][0]["in_sync"]) == {"dn1", "dn2"}


def test_client_cannot_invent_acks_when_only_one_copy_exists(cluster):
    control, _, db, _, dead, body = cluster
    dead.update(("dn2", "dn3"))
    with pytest.raises(HTTPException) as error:
        control.commit("f1", body, {"sub": "alice"})
    assert error.value.status_code == 503
    assert error.value.detail["error"] == "INSUFFICIENT_REPLICAS"
    assert db.publications == 0
    assert db.values["/files/f1"]["state"] == "PENDING"


def test_corrupt_copy_does_not_count(cluster):
    control, _, db, stores, dead, body = cluster
    dead.add("dn3")
    bid = body.changes[0]["block_id"]
    Path(stores["dn2"]._p(bid, 1)).write_bytes(b"broken")
    with pytest.raises(HTTPException) as error:
        control.commit("f1", body, {"sub": "alice"})
    assert error.value.status_code == 503
    assert db.publications == 0


def test_same_node_cannot_count_twice(cluster):
    control, _, db, _, _, body = cluster
    plan = db.values[f"/pending/{body.changes[0]['block_id']}"]
    plan["nodes"] = [plan["nodes"][0], plan["nodes"][0]]
    with pytest.raises(HTTPException) as error:
        control.commit("f1", body, {"sub": "alice"})
    assert error.value.status_code == 503
    assert db.publications == 0


@pytest.mark.parametrize("field,value", [("lock_id", "old.lock"), ("uid", "bob"), ("gen", 9)])
def test_block_must_belong_to_current_allocation(cluster, field, value):
    control, _, db, _, _, body = cluster
    db.values[f"/pending/{body.changes[0]['block_id']}"][field] = value
    with pytest.raises(HTTPException) as error:
        control.commit("f1", body, {"sub": "alice"})
    assert error.value.detail["error"] == "INVALID_ALLOCATION"
    assert db.publications == 0


def test_ciphertext_size_is_checked_against_declared_plain_size(cluster):
    control, _, db, _, _, body = cluster
    body.changes[0]["size"] = body.size = 4
    with pytest.raises(HTTPException) as error:
        control.commit("f1", body, {"sub": "alice"})
    assert error.value.status_code == 503
    assert db.publications == 0


def test_total_file_size_must_match_blocks(cluster):
    control, _, db, _, _, body = cluster
    body.size = 7
    with pytest.raises(HTTPException) as error:
        control.commit("f1", body, {"sub": "alice"})
    assert error.value.detail["error"] == "BAD_SIZE"
    assert db.publications == 0


def test_missing_block_does_not_get_verified(cluster):
    _, data, _, stores, _, body = cluster
    data.store = stores["dn1"]
    with TestClient(data.internal) as client:
        response = client.get("/internal/blocks/absent/verify?gen=1",
                              headers={"X-Cluster-Token": data.CLUSTER_TOKEN})
    assert response.status_code == 404


def test_verification_requires_cluster_authentication(cluster):
    _, data, _, _, _, body = cluster
    with TestClient(data.internal) as client:
        response = client.get(f"/internal/blocks/{body.changes[0]['block_id']}/verify?gen=1")
    assert response.status_code == 403


def test_stored_block_cannot_be_overwritten_with_other_content(tmp_path):
    from dfsha.datanode.store import BlockConflictError, Store
    store = Store(str(tmp_path))
    content = b"original"
    sha = hashlib.sha256(content).hexdigest()
    store.write("b1", 1, content, sha)
    store.write("b1", 1, content, sha)   # un reintento idéntico no falla
    with pytest.raises(BlockConflictError):
        store.write("b1", 1, b"different", hashlib.sha256(b"different").hexdigest())
    assert store.read("b1", 1)[0] == content


def test_expired_lock_cannot_publish(cluster):
    control, _, db, _, _, body = cluster
    del db.values["/locks/f1/f1.lock"]
    with pytest.raises(HTTPException) as error:
        control.commit("f1", body, {"sub": "alice"})
    assert error.value.detail["error"] == "STALE_FENCING_TOKEN"
    assert db.publications == 0


def test_old_inventory_cannot_remove_a_newly_published_copy(cluster):
    control, _, db, _, _, _ = cluster
    db.values["/files/f1"]["blocks"] = [{"in_sync": ["dn1", "dn2", "dn3"]}]

    def missing(m):
        m["blocks"][0]["in_sync"].remove("dn1")
        return True

    # El archivo se publicó en la revisión 7, después del inventario de revisión 6.
    assert not control.update_manifest("f1", missing, max_revision=6)
    assert db.values["/files/f1"]["blocks"][0]["in_sync"] == ["dn1", "dn2", "dn3"]
    assert control.update_manifest("f1", missing, max_revision=7)
    assert db.values["/files/f1"]["blocks"][0]["in_sync"] == ["dn2", "dn3"]
