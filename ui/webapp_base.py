# -*- coding: utf-8 -*-
from ui.base_store import PENDING

__all__ = ["BaseViewMixin", "PENDING_STATUS"]

PENDING_STATUS = "Не проверен"


def _pending_row(row):
    from_file = {key + "_source": "файл"
                 for key in ("name", "gender", "country") if row.get(key)}
    more = dict(from_file, pending=True)
    return {
        "email": row["email"], "avatar": "", "status": PENDING_STATUS,
        "group": PENDING, "reason": "", "score": "", "original": "",
        "confidence": "", "basis": "", "provider": row.get("provider", ""),
        "name": row.get("name", ""), "gender": row.get("gender", ""),
        "country": row.get("country", ""), "when": "", "more": more, "age": None,
    }


def _merge_facets(first, second, limit=200):
    out = {}
    for facet in set(first) | set(second):
        tally = {}
        for source in (first.get(facet) or [], second.get(facet) or []):
            for item in source:
                value = item.get("value", "")
                tally[value] = tally.get(value, 0) + int(item.get("count", 0) or 0)
        ordered = sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))
        out[facet] = [{"value": v, "count": c} for v, c in ordered[:limit]]
    return out


class BaseViewMixin:
    def _base_store(self):
        base = self.__dict__.get("base")
        if base is None or getattr(base, "_reader", None) is None:
            return None
        return base

    def _base_feeder(self):
        base = self.__dict__.get("base")
        return base.feeder() if base is not None else None

    def _base_mark(self, email, data):
        base = self.__dict__.get("base")
        if base is not None:
            base.mark(email, (data or {}).get("original_email"))

    def _base_reset(self):
        base = self.__dict__.get("base")
        if base is not None:
            base.reset_checked()

    def _base_state(self):
        base = self._base_store()
        if base is None:
            return {"total": 0, "pending": 0, "loading": False, "error": ""}
        return base.state()

    def page(self, payload):
        from ui.webapp import PAGE_SIZE

        payload = payload if isinstance(payload, dict) else {}
        picked = self._filters(payload)
        try:
            number = max(1, int(payload.get("page") or 1))
        except (TypeError, ValueError):
            number = 1

        base = self._base_store()
        checked = self.store.matching_count(filters=picked)
        pending = base.count(picked) if base is not None else 0
        total = checked + pending
        pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        number = min(number, pages)
        start = (number - 1) * PAGE_SIZE

        out = []
        if start < checked:
            out = [self._result_row(row) for row in
                   self.store.page(filters=picked, page=number, size=PAGE_SIZE)]
        room = PAGE_SIZE - len(out)
        if room > 0 and pending:
            out.extend(_pending_row(row) for row in
                       base.page(picked, max(0, start - checked), room))
        return {"rows": out, "page": number, "pages": pages, "total": total,
                "checked": checked, "pending": pending}

    def facets(self, payload=None):
        picked = self._filters(payload)
        values = self.store.facet_values(filters=picked)
        total = self.store.matching_count(filters=picked)
        base = self._base_store()
        if base is not None and PENDING in picked["groups"]:
            values = _merge_facets(values, base.facet_values(picked))
            total += base.count(picked)
        return {"facets": values, "total": total}
