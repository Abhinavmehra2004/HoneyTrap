"""
HoneyTrap Event System and Asyncio Event Bus.

Provides event models, event types enum, and an asynchronous publish-subscribe
event bus with subscriber isolation and optional storage integration.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Supported honeypot event types."""
    CONNECTION = "connection"
    AUTH_ATTEMPT = "auth_attempt"
    COMMAND = "command"
    HTTP_REQUEST = "http_request"
    FILE_UPLOAD = "file_upload"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    FTP_COMMAND = "ftp_command"


@dataclass
class HoneypotEvent:
    """Represents a security event detected by a honeypot sensor."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sensor_id: str = "honeytrap-01"
    session_id: str = ""
    protocol: str = ""  # ssh, http, ftp
    event_type: EventType = EventType.CONNECTION
    source_ip: str = ""
    source_port: int = 0
    data: dict[str, Any] = field(default_factory=dict)  # protocol-specific payload
    mitre_techniques: list[str] = field(default_factory=list)
    geo: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if isinstance(self.event_type, str) and not isinstance(self.event_type, EventType):
            try:
                self.event_type = EventType(self.event_type)
            except ValueError:
                pass
        if isinstance(self.timestamp, str):
            try:
                self.timestamp = datetime.fromisoformat(self.timestamp)
            except ValueError:
                self.timestamp = datetime.now(timezone.utc)
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert event to a JSON-serializable dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "sensor_id": self.sensor_id,
            "session_id": self.session_id,
            "protocol": self.protocol,
            "event_type": self.event_type.value if isinstance(self.event_type, EventType) else str(self.event_type),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "data": self.data,
            "mitre_techniques": self.mitre_techniques,
            "geo": self.geo,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HoneypotEvent:
        """Create a HoneypotEvent instance from a dictionary."""
        event_data = dict(data)
        event_type_val = event_data.get("event_type", EventType.CONNECTION)
        if isinstance(event_type_val, str):
            try:
                event_type = EventType(event_type_val)
            except ValueError:
                event_type = EventType.CONNECTION
        else:
            event_type = event_type_val

        ts_val = event_data.get("timestamp")
        if isinstance(ts_val, str):
            try:
                timestamp = datetime.fromisoformat(ts_val)
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        elif isinstance(ts_val, datetime):
            timestamp = ts_val
        else:
            timestamp = datetime.now(timezone.utc)

        return cls(
            id=str(event_data.get("id") or uuid.uuid4()),
            timestamp=timestamp,
            sensor_id=str(event_data.get("sensor_id", "honeytrap-01")),
            session_id=str(event_data.get("session_id", "")),
            protocol=str(event_data.get("protocol", "")),
            event_type=event_type,
            source_ip=str(event_data.get("source_ip", "")),
            source_port=int(event_data.get("source_port", 0)),
            data=event_data.get("data", {}),
            mitre_techniques=list(event_data.get("mitre_techniques", [])),
            geo=event_data.get("geo"),
        )


@dataclass
class _Subscriber:
    """Internal subscriber registration state."""
    sub_id: str
    queue: asyncio.Queue[HoneypotEvent]
    callback: Callable[[HoneypotEvent], Any] | None = None
    worker_task: asyncio.Task[None] | None = None


class EventBus:
    """
    Asynchronous event bus using asyncio.Queue per subscriber.

    Supports decoupling producers from consumers, worker error isolation,
    direct queue subscriptions for streaming (e.g., WebSockets), and optional
    persistent storage of all published events via a store backend.
    """

    def __init__(self, store: Any = None) -> None:
        """
        Initialize the EventBus.

        :param store: Optional storage layer (e.g. SQLiteStore) with save_event(event) method.
        """
        self.store = store
        self._subscribers: dict[str, _Subscriber] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    def set_store(self, store: Any) -> None:
        """Set or update the storage layer backend."""
        self.store = store

    def subscribe(self, callback: Callable[[HoneypotEvent], Any | Coroutine[Any, Any, Any]]) -> str:
        """
        Subscribe a callable handler to the event bus.

        The handler may be a synchronous function or an async coroutine. Each subscriber
        runs with its own dedicated queue and worker task so slow handlers do not block
        event publication.

        :param callback: Function or coroutine accepting a HoneypotEvent.
        :return: Unique subscriber identifier string.
        """
        sub_id = str(uuid.uuid4())
        queue: asyncio.Queue[HoneypotEvent] = asyncio.Queue(maxsize=1000)

        subscriber = _Subscriber(
            sub_id=sub_id,
            queue=queue,
            callback=callback,
        )

        try:
            loop = asyncio.get_running_loop()
            subscriber.worker_task = loop.create_task(
                self._subscriber_worker(subscriber),
                name=f"eventbus-sub-{sub_id[:8]}"
            )
        except RuntimeError:
            # If no running event loop yet, worker task will be scheduled lazily on first publish
            pass

        self._subscribers[sub_id] = subscriber
        logger.debug("Subscribed %s to event bus", sub_id)
        return sub_id

    def subscribe_queue(self, maxsize: int = 1000) -> tuple[str, asyncio.Queue[HoneypotEvent]]:
        """
        Subscribe and obtain an asyncio.Queue directly (e.g., for WebSocket streaming).

        :param maxsize: Maximum buffer size for this subscriber queue.
        :return: Tuple of (subscriber_id, queue).
        """
        sub_id = str(uuid.uuid4())
        queue: asyncio.Queue[HoneypotEvent] = asyncio.Queue(maxsize=maxsize)
        subscriber = _Subscriber(
            sub_id=sub_id,
            queue=queue,
            callback=None,
            worker_task=None,
        )
        self._subscribers[sub_id] = subscriber
        logger.debug("Subscribed queue %s to event bus", sub_id)
        return sub_id, queue

    def unsubscribe(self, sub_id: str) -> None:
        """
        Unsubscribe a subscriber and clean up its background worker.

        :param sub_id: Subscriber identifier returned by subscribe().
        """
        subscriber = self._subscribers.pop(sub_id, None)
        if subscriber is not None:
            if subscriber.worker_task is not None and not subscriber.worker_task.done():
                subscriber.worker_task.cancel()
            logger.debug("Unsubscribed %s from event bus", sub_id)

    async def _subscriber_worker(self, subscriber: _Subscriber) -> None:
        """Background worker loop processing events for a single callback subscriber."""
        callback = subscriber.callback
        if callback is None:
            return

        is_coroutine_cb = inspect.iscoroutinefunction(callback)

        while not self._closed:
            try:
                event = await subscriber.queue.get()
            except asyncio.CancelledError:
                break

            try:
                if is_coroutine_cb:
                    await callback(event)
                else:
                    res = callback(event)
                    if inspect.isawaitable(res):
                        await res
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("Error in event subscriber %s callback: %s", subscriber.sub_id, exc)
            finally:
                subscriber.queue.task_done()

    async def publish(self, event: HoneypotEvent) -> None:
        """
        Publish an event to all active subscribers and optionally persist it to store.

        :param event: The HoneypotEvent to dispatch.
        """
        if self._closed:
            logger.warning("Attempted to publish event to closed EventBus: %s", event.id)
            return

        # 1. Persist event via store if configured
        if self.store is not None:
            try:
                if hasattr(self.store, "save_event"):
                    save_res = self.store.save_event(event)
                    if inspect.isawaitable(save_res):
                        await save_res
            except Exception as exc:
                logger.error("Failed to save event %s to store: %s", event.id, exc, exc_info=True)

        # 2. Distribute to all subscribers
        subscribers = list(self._subscribers.values())
        for sub in subscribers:
            # Ensure background worker task is running for callback subscribers
            if sub.callback is not None and (sub.worker_task is None or sub.worker_task.done()):
                try:
                    loop = asyncio.get_running_loop()
                    sub.worker_task = loop.create_task(
                        self._subscriber_worker(sub),
                        name=f"eventbus-sub-{sub.sub_id[:8]}"
                    )
                except RuntimeError:
                    pass

            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("Subscriber queue %s is full; dropping oldest event", sub.sub_id)
                try:
                    _ = sub.queue.get_nowait()
                    sub.queue.task_done()
                    sub.queue.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    async def close(self) -> None:
        """Close the event bus and cancel all active subscriber tasks."""
        self._closed = True
        for sub_id, sub in list(self._subscribers.items()):
            if sub.worker_task is not None and not sub.worker_task.done():
                sub.worker_task.cancel()
        self._subscribers.clear()
