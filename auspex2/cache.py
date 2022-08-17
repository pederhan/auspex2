import json
import os
from typing import Any, Dict, List, Sequence, Type, TypeVar, Union

from loguru import logger
from pydantic import BaseModel
from redis import Redis
from redis import asyncio as aioredis

ALL_KEY = "_ALL"
DEFAULT_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

T = TypeVar("T", bound=BaseModel)


class Cache:
    def __init__(self, client: Redis) -> None:
        self.client = client

    async def get(self, key: str) -> Any:
        logger.debug("get {}", key)
        return await self.client.get(key)

    async def set(self, key: str, value: Any) -> None:
        logger.debug("set {}", key, value)
        return await self.client.set(key, value)


clients: Dict[str, Cache] = {}  # keys: URLs, values: clients


async def init_client(url: str = DEFAULT_URL) -> None:
    await get_cache(url)


async def get_cache(url: str = DEFAULT_URL) -> Cache:
    if url not in clients:
        clients[url] = Cache(await aioredis.from_url(url))
    return clients[url]


class JsonabbleSequence(BaseModel):
    __root__: Sequence[BaseModel]


async def _get_cache_key(key: Union[str, Sequence[str]], type: Type[BaseModel]) -> str:
    if isinstance(key, Sequence):
        key = "".join(key)
    type_name = repr(type).split("'")[1]
    return f"{type_name}_{key}"


async def get_cached(type: Type[T], key: Union[str, List[str]]) -> List[T]:
    cache = await get_cache()
    cache_key = await _get_cache_key(key, type)
    cached = await cache.get(cache_key)
    if not cached:
        return []

    if isinstance(cached, bytes):
        cached = cached.decode("utf-8")

    json_data = json.loads(cached)
    res = [type.parse_obj(item) for item in json_data]
    return res


async def set_cached(
    type: Type[T], key: Union[str, List[str]], data: Sequence[T]
) -> None:
    cache = await get_cache()
    cache_key = await _get_cache_key(key, type)
    json_data = JsonabbleSequence(__root__=data).json()
    await cache.set(cache_key, json_data)


# async def get(key: str) -> Any:
#     logger.debug("get {}", key)
#     return await client.get(key)


# async def set(key: str, value: Any) -> None:
#     logger.debug("set {}: {}", key, value)
#     return await client.set(key, value)
