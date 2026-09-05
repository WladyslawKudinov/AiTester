"""Discovery векторов атак — НОЛЬ регистрации.

Атаку кладут папкой attack_vectors/<name>/ с vector.py (подкласс AttackVector), README.md и
params.yaml. discover() сканит папки, импортит vector.py, находит подкласс ИНТРОСПЕКЦИЕЙ
(issubclass), подгружает params.yaml рядом. Регистрировать нигде не надо, ручных списков нет.
Сбойная атака не роняет весь скан (try/except на модуль -> варнинг). Конвенция как у pytest
(сбор без регистрации) и ansible/terraform (модуль = папка по имени).
"""

import importlib
import importlib.util
import inspect
import os
import sys
import warnings

import yaml

from .base import AttackVector

_PKG = __name__.rsplit(".", 1)[0]                 # harness.attack_vectors
_DIR = os.path.dirname(os.path.abspath(__file__))


def _import_vector_module(pkg, entry, folder):
    """Импортировать <folder>/vector.py как pkg.<entry>.vector БЕЗ __init__.py в папке атаки.
    Синтетический подпакет pkg.<entry> с __path__ даёт резолв относительных импортов
    (from ..base import AttackVector) — автор просто кладёт папку, ничего не регистрируя."""
    modname = f"{pkg}.{entry}.vector"
    if modname in sys.modules:
        return sys.modules[modname]
    subpkg = f"{pkg}.{entry}"
    if subpkg not in sys.modules:
        spec_pkg = importlib.machinery.ModuleSpec(subpkg, loader=None, is_package=True)
        m = importlib.util.module_from_spec(spec_pkg)
        m.__path__ = [folder]
        sys.modules[subpkg] = m
    spec = importlib.util.spec_from_file_location(modname, os.path.join(folder, "vector.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_params_yaml(folder):
    """params.yaml рядом с vector.py -> (defaults, schema).
    Формат ключа: 'key: {type,default,required,options?,description}' ИЛИ короткий 'key: value'."""
    path = os.path.join(folder, "params.yaml")
    if not os.path.exists(path):
        return {}, {}
    data = yaml.safe_load(open(path, encoding="utf-8")) or {}
    spec = data.get("params", data) if isinstance(data, dict) else {}
    defaults, schema = {}, {}
    for k, v in (spec or {}).items():
        if isinstance(v, dict) and ("default" in v or "type" in v):
            schema[k] = v
            defaults[k] = v.get("default")
        else:                                     # короткая форма 'key: value'
            defaults[k] = v
            schema[k] = {"default": v, "type": type(v).__name__}
    return defaults, schema


def _find_vector_class(mod):
    """Подкласс AttackVector, ОПРЕДЕЛЁННЫЙ в этом модуле (не импортированный базовый)."""
    found = None
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if (issubclass(obj, AttackVector) and obj is not AttackVector
                and obj.__module__ == mod.__name__):
            found = obj
    return found


def discover(pkg=None):
    """Найти все векторы. -> {name: class}. pkg — переопределение пакета (для тестов)."""
    pkg = pkg or _PKG
    base_dir = _DIR if pkg == _PKG else os.path.dirname(importlib.import_module(pkg).__file__)
    registry = {}
    for entry in sorted(os.listdir(base_dir)):
        folder = os.path.join(base_dir, entry)
        if entry.startswith("_") or entry.startswith(".") or not os.path.isdir(folder):
            continue
        if not os.path.exists(os.path.join(folder, "vector.py")):
            continue
        try:
            mod = _import_vector_module(pkg, entry, folder)
            cls = _find_vector_class(mod)
            if cls is None:
                warnings.warn(f"attack_vectors/{entry}: нет подкласса AttackVector — пропуск")
                continue
            if not cls.name:
                cls.name = entry
            cls._param_defaults, cls._param_schema = _load_params_yaml(folder)
            cls._folder = folder
            registry[cls.name] = cls
        except Exception as e:                    # сбойная атака не роняет скан
            warnings.warn(f"attack_vectors/{entry}: ошибка загрузки "
                          f"({type(e).__name__}: {str(e)[:120]}) — пропуск")
    return registry


def merge_params(cls, cli_overrides):
    """Слить параметры с precedence: params.yaml (дефолт) < CLI '<vector>--k=v'.
    Неизвестный ключ НЕ роняет прогон — варнинг (решение юзера), ключ игнорируется.
    -> dict валидных параметров для конструктора вектора."""
    schema = getattr(cls, "_param_schema", {}) or {}
    defaults = dict(getattr(cls, "_param_defaults", {}) or {})
    for k, raw in (cli_overrides or {}).items():
        if schema and k not in schema:
            known = ", ".join(sorted(schema)) or "(нет объявленных параметров)"
            warnings.warn(f"неизвестный параметр '{k}' для вектора '{cls.name}' — игнорирую; "
                          f"известные: {known}")
            continue
        defaults[k] = _coerce(raw, schema.get(k, {}))
    return defaults


def _coerce(raw, spec):
    """Привести CLI-строку к типу из схемы (int/float/bool/list через запятую); иначе как есть."""
    if not isinstance(raw, str):
        return raw
    t = (spec or {}).get("type")
    try:
        if t in ("int",):
            return int(raw)
        if t in ("float",):
            return float(raw)
        if t in ("bool",):
            return raw.strip().lower() in ("1", "true", "yes", "on", "да")
        if t in ("list",):
            return [x.strip() for x in raw.split(",") if x.strip()]
    except ValueError:
        warnings.warn(f"не смог привести '{raw}' к типу {t} — беру строкой")
    return raw
