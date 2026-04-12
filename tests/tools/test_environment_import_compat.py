import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_module(module_name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_modal_import_survives_older_base_helpers(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "tools.environments.base",
        types.SimpleNamespace(BaseEnvironment=type("BaseEnvironment", (), {})),
    )

    module = _load_module("tools.environments.modal", "tools/environments/modal.py")

    assert callable(module._load_json_store)
    assert callable(module._save_json_store)
    assert callable(module._file_mtime_key)
    assert hasattr(module, "_ThreadedProcessHandle")



def test_singularity_import_survives_older_base_helpers(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "tools.environments.base",
        types.SimpleNamespace(BaseEnvironment=type("BaseEnvironment", (), {})),
    )

    module = _load_module("tools.environments.singularity", "tools/environments/singularity.py")

    assert callable(module._load_json_store)
    assert callable(module._save_json_store)
    assert callable(module._popen_bash)
