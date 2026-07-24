#!/usr/bin/env python3
# core/async_runtime.py — Central Async Runtime Manager
# Buildmap: Remove time.sleep(), unmanaged threads, blocking calls
# ALL orchestration must live inside one asyncio event loop
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import asyncio, threading, time
from typing import Callable, Awaitable, Any
from core.error_handler import get_handler


class AsyncRuntime:
    """
    Central async runtime — the only event loop for M7Hunter.

    Rules:
    - ONE shared event loop for all engines, scheduler, browser, AI
    - NO time.sleep() anywhere — use await asyncio.sleep()
    - NO unmanaged threads — use loop.run_in_executor() for blocking I/O
    - NO rogue background tasks — all tasks registered here
    - Full async cancellation support
    """

    def __init__(self, log=None):
        self.log        = log
        self._loop      : asyncio.AbstractEventLoop | None = None
        self._thread    : threading.Thread | None = None
        self._tasks     : dict[str, asyncio.Task] = {}
        self._lock      = threading.Lock()
        self._started   = False
        self._shutdown  : asyncio.Event | None = None  # created in loop thread

    def start(self):
        """Start the shared event loop in a dedicated daemon thread."""
        if self._started:
            return
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name="m7-async-runtime", daemon=True
        )
        self._thread.start()
        self._started = True
        if self.log:
            self.log.info("[AsyncRuntime] Started shared event loop")

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    def submit(self, coro: Awaitable, name: str = "", timeout: float = None) -> asyncio.Future:
        """Submit a coroutine to the shared loop. Returns a concurrent Future."""
        if not self._loop or not self._started:
            raise RuntimeError("AsyncRuntime not started")
        if timeout:
            coro = asyncio.wait_for(coro, timeout=timeout)
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        if name:
            with self._lock:
                self._tasks[name] = future
        return future

    def submit_and_wait(self, coro: Awaitable, name: str = "",
                        timeout: float = 300) -> Any:
        """Submit coroutine and block until result (for sync callers)."""
        future = self.submit(coro, name=name, timeout=timeout)
        try:
            return future.result(timeout=timeout + 5)
        except asyncio.TimeoutError:
            future.cancel()
            get_handler().capture("async_runtime", asyncio.TimeoutError(), f"timeout:{name}")
            return None
        except Exception as e:
            get_handler().capture("async_runtime", e, f"submit_wait:{name}")
            return None

    async def sleep(self, seconds: float):
        """Async sleep — replaces time.sleep() everywhere."""
        await asyncio.sleep(seconds)

    def sleep_sync(self, seconds: float):
        """Sync-safe sleep that doesn't block the event loop."""
        if self._loop and self._loop.is_running():
            future = asyncio.run_coroutine_threadsafe(
                asyncio.sleep(seconds), self._loop
            )
            future.result(timeout=seconds + 1)
        else:
            time.sleep(seconds)

    def cancel_task(self, name: str) -> bool:
        with self._lock:
            task = self._tasks.pop(name, None)
        if task and not task.done():
            task.cancel()
            return True
        return False

    def cancel_all(self):
        """Cancel all registered tasks — called on emergency shutdown."""
        with self._lock:
            names = list(self._tasks.keys())
        for name in names:
            self.cancel_task(name)
        if self.log:
            self.log.warn(f"[AsyncRuntime] Cancelled {len(names)} tasks")

    def get_active_tasks(self) -> list[str]:
        with self._lock:
            return [n for n, t in self._tasks.items() if not t.done()]

    def shutdown(self, wait: bool = True):
        """Graceful shutdown — cancel tasks, stop loop."""
        self.cancel_all()
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if wait and self._thread:
            self._thread.join(timeout=10)
        self._started = False
        if self.log:
            self.log.info("[AsyncRuntime] Shutdown complete")

    @property
    def loop(self) -> asyncio.AbstractEventLoop | None:
        return self._loop

    @property
    def is_running(self) -> bool:
        return self._started and self._loop is not None and self._loop.is_running()

    def status(self) -> dict:
        active = self.get_active_tasks()
        return {
            "running"      : self.is_running,
            "active_tasks" : len(active),
            "task_names"   : active,
        }


# Module-level singleton
_runtime: AsyncRuntime | None = None

def get_runtime(log=None) -> AsyncRuntime:
    global _runtime
    if _runtime is None:
        _runtime = AsyncRuntime(log=log)
        _runtime.start()
    return _runtime

def async_sleep(seconds: float):
    """Drop-in async-safe replacement for time.sleep()."""
    get_runtime().sleep_sync(seconds)
