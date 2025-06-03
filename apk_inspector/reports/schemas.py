
from typing import List, Dict, Any, Set
from pydantic import BaseModel, Field, field_validator


class YaraMatchModel(BaseModel):
    rule: str
    tags: List[str] = []
    meta: Dict[str, Any] = {}
    file: str = ""
    strings: List[Any] = []
    namespace: str = ""

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, v):
        if isinstance(v, set):
            v = list(v)
        if not isinstance(v, list):
            return [str(v)]
        return [str(tag).lower() for tag in v]

    @field_validator("meta", mode="before")
    @classmethod
    def normalize_meta(cls, v):
        if not isinstance(v, dict):
            raise TypeError(f"Expected meta to be dict, got {type(v)}")
        return v