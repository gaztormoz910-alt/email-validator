# -*- coding: utf-8 -*-
import secrets
import threading

__all__ = ["CanaryWatch", "canary_address", "CANARY_MARK"]

CANARY_MARK = "-canary-"

_ДЛИНА = 24
_АЛФАВИТ = "abcdefghijkmnopqrstuvwxyz23456789"


def canary_address(domain):
    хвост = "".join(secrets.choice(_АЛФАВИТ) for _ in range(_ДЛИНА))
    local = "zz" + CANARY_MARK + хвост
    return "%s@%s" % (local[:64], domain)


_ОТКАЗ_ВЫДУМАННОМУ = ("invalid", "risky", "disabled")


class CanaryWatch(object):

    REPEAT_EVERY = 20

    def __init__(self, every=1, min_valid=1, repeat=None):
        self.every = max(1, int(every))
        self.min_valid = max(1, int(min_valid))
        self.repeat = max(1, int(repeat if repeat is not None else self.REPEAT_EVERY))
        self._lock = threading.Lock()
        self._probed_at = {}
        self._honest_upto = {}
        self._valid = {}
        self._в_полёте = {}
        self._probed = set()
        self._врут = set()
        self.поймано = 0
        self.проб = 0


    @staticmethod
    def _пара(exit_ip, domain):
        return (str(exit_ip or "прямое соединение").lower(),
                str(domain or "").lower())

    def note_valid(self, exit_ip, domain):
        ключ = self._пара(exit_ip, domain)
        with self._lock:
            self._valid[ключ] = self._valid.get(ключ, 0) + 1
            return self._valid[ключ]

    def should_probe(self, exit_ip, domain):
        return self.claim_probe(exit_ip, domain) is not None

    def claim_probe(self, exit_ip, domain):
        ключ = self._пара(exit_ip, domain)
        with self._lock:
            if ключ in self._врут or ключ in self._в_полёте:
                # Уличён — пробовать незачем. Летит проба — вторую не пускаем:
                return None
            набрано = self._valid.get(ключ, 0)
            if набрано < self.min_valid:
                return None
            if ключ not in self._probed:
                пора = набрано % self.every == 0
            else:
                пора = набрано - self._probed_at.get(ключ, 0) >= self.repeat
            if not пора:
                return None
            self._probed_at[ключ] = набрано
            self._в_полёте[ключ] = набрано
            return набрано

    def claim_now(self, exit_ip, domain):
        ключ = self._пара(exit_ip, domain)
        with self._lock:
            набрано = self._valid.get(ключ, 0)
            self._probed_at[ключ] = набрано
            self._в_полёте[ключ] = набрано
            return набрано

    def release(self, exit_ip, domain, covers):
        ключ = self._пара(exit_ip, domain)
        with self._lock:
            if self._в_полёте.get(ключ) == covers:
                del self._в_полёте[ключ]

    def valid_count(self, exit_ip, domain):
        with self._lock:
            return self._valid.get(self._пара(exit_ip, domain), 0)

    def honest_upto(self, exit_ip, domain):
        ключ = self._пара(exit_ip, domain)
        with self._lock:
            if ключ in self._врут or ключ not in self._probed:
                return -1
            return self._honest_upto.get(ключ, -1)

    def record(self, exit_ip, domain, status, covers=None):
        ключ = self._пара(exit_ip, domain)
        status = str(status or "").lower()
        врёт = status in ("valid", "catchall")
        честен = status in _ОТКАЗ_ВЫДУМАННОМУ
        with self._lock:
            self.проб += 1
            if covers is None or self._в_полёте.get(ключ) == covers:
                self._в_полёте.pop(ключ, None)
            if not врёт and not честен:
                return False
            self._probed.add(ключ)
            if врёт:
                self._врут.add(ключ)
                self.поймано += 1
            else:
                if covers is not None:
                    покрыто = int(covers)
                else:
                    покрыто = self._probed_at.get(ключ, self._valid.get(ключ, 0))
                self._honest_upto[ключ] = max(self._honest_upto.get(ключ, -1), покрыто)
        return врёт


    def is_compromised(self, exit_ip, domain):
        with self._lock:
            return self._пара(exit_ip, domain) in self._врут

    def vouched(self, exit_ip, domain):
        ключ = self._пара(exit_ip, domain)
        with self._lock:
            return ключ in self._probed and ключ not in self._врут

    def lying_pairs(self):
        with self._lock:
            return set(self._врут)

    def compromised_domains(self):
        with self._lock:
            return sorted({домен for _выход, домен in self._врут})

    def summary(self):
        with self._lock:
            return {"проб": self.проб, "поймано": self.поймано,
                    "домены": sorted({d for _e, d in self._врут})}
