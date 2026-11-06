import re
from bson import ObjectId
from typing import Dict, Any, List, Optional

class InMemoryCursor:
    def __init__(self, docs: List[Dict[str, Any]]):
        self._docs = list(docs)
        self._skip_val = 0
        self._limit_val = None

    def skip(self, n: int):
        self._skip_val = n
        return self

    def limit(self, n: int):
        self._limit_val = n
        return self

    def sort(self, sort_by, direction=1):
        if not sort_by:
            return self
        if isinstance(sort_by, str):
            key = sort_by
            reverse = direction < 0
            if key.startswith("-"):
                key = key[1:]
                reverse = True
            self._docs.sort(key=lambda d: d.get(key, 0) or 0, reverse=reverse)
        elif isinstance(sort_by, list):
            for field, order in reversed(sort_by):
                reverse = order < 0
                self._docs.sort(key=lambda d: d.get(field, 0) or 0, reverse=reverse)
        return self

    async def to_list(self, length: Optional[int] = None):
        res = self._docs[self._skip_val:]
        limit = self._limit_val if self._limit_val is not None else length
        if limit is not None:
            res = res[:limit]
        return [dict(d) for d in res]


class InMemoryCollection:
    def __init__(self, name: str):
        self.name = name
        self._docs: List[Dict[str, Any]] = []

    def _matches(self, doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
        if not query:
            return True
        for k, v in query.items():
            if k == "$or":
                sub_matched = any(self._matches(doc, sub_q) for sub_q in v)
                if not sub_matched:
                    return False
                continue
            if k == "_id":
                if str(doc.get("_id")) != str(v):
                    return False
                continue
            if isinstance(v, dict):
                val = doc.get(k)
                for op, op_val in v.items():
                    if op == "$gte" and not (val is not None and val >= op_val):
                        return False
                    if op == "$lte" and not (val is not None and val <= op_val):
                        return False
                    if op == "$gt" and not (val is not None and val > op_val):
                        return False
                    if op == "$lt" and not (val is not None and val < op_val):
                        return False
                    if op == "$ne" and val == op_val:
                        return False
                continue
            if doc.get(k) != v:
                return False
        return True

    async def find_one(self, query: Dict[str, Any]):
        for d in self._docs:
            if self._matches(d, query):
                return dict(d)
        return None

    async def insert_one(self, doc: Dict[str, Any]):
        new_doc = dict(doc)
        if "_id" not in new_doc:
            new_doc["_id"] = ObjectId()
        self._docs.append(new_doc)
        class InsertResult:
            def __init__(self, inserted_id):
                self.inserted_id = inserted_id
        return InsertResult(new_doc["_id"])

    async def update_one(self, query: Dict[str, Any], update: Dict[str, Any]):
        matched = 0
        modified = 0
        for d in self._docs:
            if self._matches(d, query):
                matched += 1
                if "$set" in update:
                    for sk, sv in update["$set"].items():
                        d[sk] = sv
                        modified += 1
                if "$push" in update:
                    for pk, pv in update["$push"].items():
                        if pk not in d or not isinstance(d[pk], list):
                            d[pk] = []
                        d[pk].append(pv)
                        modified += 1
                if "$inc" in update:
                    for ik, iv in update["$inc"].items():
                        d[ik] = d.get(ik, 0) + iv
                        modified += 1
                break
        class UpdateResult:
            def __init__(self, m, mod):
                self.matched_count = m
                self.modified_count = mod
        return UpdateResult(matched, modified)

    async def delete_one(self, query: Dict[str, Any]):
        count = 0
        for idx, d in enumerate(self._docs):
            if self._matches(d, query):
                del self._docs[idx]
                count = 1
                break
        class DeleteResult:
            def __init__(self, c):
                self.deleted_count = c
        return DeleteResult(count)

    def find(self, query: Optional[Dict[str, Any]] = None):
        q = query or {}
        matched = [d for d in self._docs if self._matches(d, q)]
        return InMemoryCursor(matched)

    async def count_documents(self, query: Optional[Dict[str, Any]] = None):
        q = query or {}
        return len([d for d in self._docs if self._matches(d, q)])

    async def create_index(self, *args, **kwargs):
        return True


class InMemoryDatabase:
    def __init__(self):
        self._collections: Dict[str, InMemoryCollection] = {}

    def __getitem__(self, name: str) -> InMemoryCollection:
        if name not in self._collections:
            self._collections[name] = InMemoryCollection(name)
        return self._collections[name]

    class AdminMock:
        async def command(self, *args, **kwargs):
            return {"ok": 1}

    @property
    def admin(self):
        return self.AdminMock()

    async def list_collection_names(self):
        return list(self._collections.keys())

