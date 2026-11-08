"""Hashing consistente con nodos virtuales."""
import bisect
import hashlib


def h64(s):
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:8], "big")


class Ring:
    def __init__(self, nodes, vnodes=128):
        self.nodes = list(nodes)
        self.pts = sorted((h64(f"{n}#{v}"), n) for n in self.nodes for v in range(vnodes))
        self.keys = [p[0] for p in self.pts]

    def walk(self, key):
        """Nodos distintos en orden de anillo a partir de la posición de la clave."""
        if not self.pts:
            return []
        i = bisect.bisect(self.keys, h64(key)) % len(self.pts)
        seen = []
        for k in range(len(self.pts)):
            n = self.pts[(i + k) % len(self.pts)][1]
            if n not in seen:
                seen.append(n)
                if len(seen) == len(self.nodes):
                    break
        return seen

    def pick(self, key, n=3, load=None, margin=1.25, slack=8):
        """n nodos distintos según el anillo. Desempate por ocupación: si uno de los elegidos está
        mucho más lleno que el siguiente candidato del anillo, se cambia por este último."""
        order = self.walk(key)
        chosen, extra = order[:n], order[n:n + 1]
        if load and extra:
            worst = max(chosen, key=lambda x: load.get(x, 0))
            if load.get(worst, 0) > load.get(extra[0], 0) * margin + slack:
                chosen[chosen.index(worst)] = extra[0]
        return chosen
