"""#4515 — one event loop and one async engine per prefork child."""

import asyncio
import os

import pytest

from app import task_runtime


@pytest.fixture
def child(monkeypatch):
    """Install a child loop, counting engines built, and tear it down."""
    built = []
    real = task_runtime.create_async_engine

    def spy(*a, **kw):
        eng = real(*a, **kw)
        built.append(eng)
        return eng

    monkeypatch.setattr(task_runtime, "create_async_engine", spy)
    task_runtime.close_child_loop()
    task_runtime.install_child_loop()
    try:
        yield built
    finally:
        task_runtime.close_child_loop()


def _task_shaped():
    async def body():
        eng = task_runtime.task_engine()
        try:
            return eng, asyncio.get_running_loop()
        finally:
            await task_runtime.release_task_engine(eng)

    return body()


def test_many_runs_share_one_loop_and_one_engine(child):
    results = [task_runtime.run_task(_task_shaped()) for _ in range(25)]
    assert len(child) == 1
    assert len({id(e) for e, _ in results}) == 1
    assert len({id(lp) for _, lp in results}) == 1


def test_command_timeout_gets_its_own_engine(child):
    async def two():
        a = task_runtime.task_engine()
        b = task_runtime.task_engine(900.0)
        return a, b, task_runtime.task_engine(900.0)

    a, b, b2 = task_runtime.run_task(two())
    assert a is not b and b is b2
    assert len(child) == 2


def test_failed_run_leaves_loop_usable(child):
    held = []

    async def boom():
        async def leftover():
            await asyncio.sleep(3600)

        held.append(asyncio.ensure_future(leftover()))
        await asyncio.sleep(0)
        raise ValueError("task failed")

    with pytest.raises(ValueError):
        task_runtime.run_task(boom())
    loop = task_runtime._state.loop
    assert not loop.is_closed()
    assert held[0].cancelled()
    # the leftover task was cancelled, not carried into the next run
    assert not [t for t in asyncio.all_tasks(loop) if not t.done()]
    eng, lp = task_runtime.run_task(_task_shaped())
    assert lp is loop
    assert len(child) == 1


def test_cancelled_midway_run_does_not_poison_loop(child):
    async def hang():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        task_runtime.run_task(hang())
    assert task_runtime.run_task(_task_shaped())[1] is task_runtime._state.loop


def test_without_child_loop_falls_back_to_asyncio_run_and_throwaway_engine(monkeypatch):
    task_runtime.close_child_loop()
    built = []
    real = task_runtime.create_async_engine
    monkeypatch.setattr(
        task_runtime, "create_async_engine", lambda *a, **k: built.append(1) or real(*a, **k)
    )
    r1 = task_runtime.run_task(_task_shaped())
    r2 = task_runtime.run_task(_task_shaped())
    assert len(built) == 2
    assert r1[0] is not r2[0]
    assert r1[1] is not r2[1]


def test_engine_is_not_shared_on_a_foreign_loop(child):
    """An ``asyncio.run`` loop inside a child must not see the child's engine
    (its connections belong to the child loop)."""

    async def other():
        return task_runtime.task_engine()

    shared = task_runtime.run_task(other())
    foreign = asyncio.run(other())
    assert foreign is not shared
    asyncio.run(foreign.dispose())


def test_forked_state_is_discarded(child):
    task_runtime.run_task(_task_shaped())
    st = task_runtime._state
    assert st is not None and st.pid == os.getpid()
    st.pid = os.getpid() + 1  # pretend this is a copy inherited over a fork
    assert task_runtime._current() is None
    assert task_runtime._state is None
    # a fresh install after the "fork" builds its own loop and engine
    task_runtime.install_child_loop()
    assert task_runtime._state is not st
    task_runtime.run_task(_task_shaped())
    assert len(child) == 2


def test_close_disposes_engines_and_loop(child):
    task_runtime.run_task(_task_shaped())
    loop = task_runtime._state.loop
    task_runtime.close_child_loop()
    assert loop.is_closed()
    assert task_runtime._state is None


def test_task_session_frees_session_advisory_locks(child):
    """The shared connection outlives the task, so a session-level advisory
    lock must not survive it (the throwaway engine's dispose used to drop it)."""
    from sqlalchemy import text

    from app.db import task_session

    async def take():
        async with task_session() as db:
            assert (await db.execute(text("select pg_try_advisory_lock(4515)"))).scalar()

    async def probe():
        async with task_session() as db:
            got = (await db.execute(text("select pg_try_advisory_lock(4515)"))).scalar()
            if got:
                await db.execute(text("select pg_advisory_unlock(4515)"))
            return got

    task_runtime.run_task(take())
    assert task_runtime.run_task(probe()) is True
