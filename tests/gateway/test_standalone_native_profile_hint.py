"""Standalone native ingress accepts only the launch profile's own optional label."""
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter
from gateway.platforms.event import MessageEvent, MessageType
from gateway.run import GatewayRunner
from gateway.run_runtime import initialize_gateway_runtime
from gateway.runtime_ownership import process_ownership
from gateway.session_envelope import prepare_native, restore_native
from gateway.session_ingress_context import native_callback, register_transport_home
from hermes_state_runtime import RuntimeStoreError


class _Adapter(BasePlatformAdapter):
    pass


_Adapter.__abstractmethods__ = frozenset()


@asynccontextmanager
async def _standalone(tmp_path, monkeypatch, name):
    root = tmp_path / '.hermes'
    home = root if name == 'default' else root / 'profiles' / name
    home.mkdir(parents=True)
    (home / 'config.yaml').write_text('{}', encoding='utf-8')
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    monkeypatch.setenv('HERMES_HOME', str(home))
    import hermes_constants
    monkeypatch.setattr(hermes_constants, '_PINNED_PROCESS_HERMES_HOME', str(home))
    import hermes_state
    # Let SessionDB resolve this fixture's home, not conftest's earlier home.
    monkeypatch.setattr(hermes_state, 'DEFAULT_DB_PATH', hermes_state._IMPORT_DEFAULT_DB_PATH)
    runner = GatewayRunner(GatewayConfig(sessions_dir=home / 'sessions', multiplex_profiles=False))
    runner._primary_profile_name = name
    process_ownership.reserve([home])
    try:
        await initialize_gateway_runtime(runner)
        adapter = _Adapter(PlatformConfig(enabled=True), Platform.SLACK)
        adapter.gateway_runner = runner
        runner.adapters = {Platform.SLACK: adapter}
        # Profile provenance and sender authorization are independent checks.
        runner._is_user_authorized_for_source = lambda *args, **kwargs: True
        register_transport_home(runner, None, home)
        source = adapter.build_source(chat_id='fixture-chat', chat_type='group',
                                      user_id='fixture-user', scope_id='fixture-scope')
        event = MessageEvent(text='hello', message_id='fixture-input',
                             message_type=MessageType.TEXT, source=source)
        yield runner, adapter, event, home
    finally:
        for authority in list(getattr(runner, 'session_authorities', []) or []):
            authority.db.close()
        process_ownership.release(home)


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['default', 'ops', 'research'])
@pytest.mark.parametrize('with_hint', [False, True])
@pytest.mark.parametrize('after_pin', [False, True])
@pytest.mark.parametrize('mirror', [False, True])
async def test_standalone_native_round_trip_keeps_launch_home_and_namespace(
    tmp_path, monkeypatch, name, with_hint, after_pin, mirror,
):
    async with _standalone(tmp_path, monkeypatch, name) as (runner, adapter, event, home):
        if with_hint and not after_pin:
            event.source.profile = name
        runner._canonicalize(event.source)
        if with_hint and after_pin:
            event.source.profile = name
        if mirror:
            # Embedding hosts may mirror a different active home into the environment.
            other = tmp_path / 'mirrored-home'
            other.mkdir()
            monkeypatch.setenv('HERMES_HOME', str(other))
        with native_callback(runner, event, home):
            payload = await prepare_native(runner, event)
        envelope = payload['native_text_v1']
        assert envelope['route'].startswith('agent:main:')
        assert envelope['provenance']['runtime_home'] == str(home.resolve())
        assert envelope['provenance']['transport_home'] == str(home.resolve())
        restored = restore_native(payload, runner)
        assert restored.source.profile == event.source.profile
        assert runner._adapter_for_source(restored.source) is adapter
        assert runner._session_key_for_source(restored.source) == envelope['route']
        forged = deepcopy(payload)
        forged['native_text_v1']['source']['profile'] = 'other'
        with pytest.raises(RuntimeStoreError, match='profile_mismatch'):
            restore_native(forged, runner)


@pytest.mark.asyncio
@pytest.mark.parametrize('after_pin', [False, True])
@pytest.mark.parametrize('hint, foreign_home, callback_profile, duplicate, authorized, error', [
    ('research', False, None, False, True, 'profile_mismatch'),
    ('unknown', False, None, False, True, 'profile_mismatch'),
    ('../research', False, None, False, True, 'profile_mismatch'),
    ('ops', True, None, False, True, 'profile_mismatch'),
    ('ops', False, 'ops', False, True, 'profile_mismatch'),
    ('ops', False, None, True, True, 'not_found'),
    ('ops', False, None, False, False, 'permission_denied'),
])
async def test_standalone_hint_cannot_change_ownership_or_authorization(
    tmp_path, monkeypatch, after_pin, hint, foreign_home, callback_profile, duplicate, authorized, error,
):
    async with _standalone(tmp_path, monkeypatch, 'ops') as (runner, adapter, event, home):
        if not after_pin:
            event.source.profile = hint
        runner._canonicalize(event.source)
        if after_pin:
            event.source.profile = hint
        callback_home = home
        if foreign_home:
            callback_home = home.parent / 'research'
            callback_home.mkdir()
            register_transport_home(runner, None, callback_home)
        if callback_profile is not None:
            secondary = _Adapter(PlatformConfig(enabled=True), Platform.SLACK)
            secondary.gateway_runner = runner
            runner._profile_adapters = {callback_profile: {Platform.SLACK: secondary}}
            register_transport_home(runner, callback_profile, home)
        if duplicate:
            runner._profile_adapters = {'research': {Platform.SLACK: adapter}}
        runner._is_user_authorized_for_source = lambda *args, **kwargs: authorized
        with native_callback(runner, event, callback_home, callback_profile):
            with pytest.raises(RuntimeStoreError, match=error):
                await prepare_native(runner, event)
