#!/usr/bin/env python3
# core/plugin_loader.py — V7 Plugin Architecture
# Auto-discovers engines/plugins from plugins/ and engines/ directories
# MilkyWay Intelligence | Author: Sharlix

import os
import sys
import importlib
import importlib.util
from typing import Dict, List, Type, Any


class PluginMeta:
    """Metadata for a loaded plugin."""
    def __init__(self, name: str, module: Any, cls: Any, path: str):
        self.name    = name
        self.module  = module
        self.cls     = cls
        self.path    = path
        self.enabled = True

    def __repr__(self):
        return f"Plugin({self.name}, enabled={self.enabled})"


class PluginLoader:
    """
    V7 Plugin Loader.

    Discovers modules in:
    - plugins/    (custom user plugins)
    - engines/    (built-in engines)
    - modules/    (step modules)

    Each plugin must have a class matching the filename (CamelCase).
    E.g. engines/xss_engine.py → class XssEngine
    """

    def __init__(self, base_dir: str, log=None):
        self.base_dir = base_dir
        self.log      = log
        self._plugins : Dict[str, PluginMeta] = {}

    def discover(self, folders: List[str] = None) -> Dict[str, PluginMeta]:
        """Auto-discover plugins in specified folders."""
        folders = folders or ["plugins", "engines", "modules"]
        for folder in folders:
            folder_path = os.path.join(self.base_dir, folder)
            if not os.path.isdir(folder_path):
                continue
            for filename in sorted(os.listdir(folder_path)):
                if not filename.endswith(".py") or filename.startswith("_"):
                    continue
                module_name = filename[:-3]
                plugin_path = os.path.join(folder_path, filename)
                self._load_plugin(module_name, plugin_path, folder)
        return self._plugins

    def _load_plugin(self, name: str, path: str, folder: str):
        """Load a single plugin file."""
        try:
            spec   = importlib.util.spec_from_file_location(
                f"m7v7.{folder}.{name}", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find the main class (CamelCase of filename)
            cls_name = "".join(w.capitalize() for w in name.split("_"))
            cls = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and
                        attr_name.lower().replace("_","") == cls_name.lower().replace("_","")):
                    cls = attr
                    break

            if cls is None:
                # Try any class that has a run() method
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and hasattr(attr, "run") and attr_name != "type":
                        cls = attr
                        break

            meta = PluginMeta(name, module, cls, path)
            self._plugins[name] = meta

        except Exception as e:
            if self.log:
                self.log.warn(f"[Plugin] Failed to load {name}: {e}")

    def get(self, name: str) -> PluginMeta:
        return self._plugins.get(name)

    def get_steps(self) -> Dict[str, Type]:
        """Return step modules (step01_, step02_, etc.) as {step_name: class}."""
        steps = {}
        for name, meta in self._plugins.items():
            if name.startswith("step") and meta.cls:
                # Extract step name from class or name
                step_key = name.replace("step", "").lstrip("0123456789_").lower()
                if not step_key:
                    continue
                # Map numeric prefix to step name
                NUM_TO_NAME = {
                    "01":"subdomain","02":"dns","03":"probe","04":"ports","05":"crawl",
                    "06":"nuclei","07":"xss","08":"sqli","09":"cors","10":"lfi",
                    "11":"ssrf","12":"redirect","13":"takeover","14":"screenshot",
                    "15":"wpscan","16":"github","17":"cloud","18":"ssti","19":"jwt",
                    "20":"graphql","21":"host_header","22":"idor","23":"xxe",
                    "24":"smuggling","25":"csrf","26":"race","27":"nosql","28":"ws","29":"proto_pollution",
                }
                num = name[4:6] if len(name) > 5 else name[4:5]
                key = NUM_TO_NAME.get(num, step_key)
                steps[key] = meta.cls
        return steps

    def list_enabled(self) -> List[str]:
        return [name for name, meta in self._plugins.items() if meta.enabled]

    def disable(self, name: str):
        if name in self._plugins:
            self._plugins[name].enabled = False

    def enable(self, name: str):
        if name in self._plugins:
            self._plugins[name].enabled = True

    def reload(self, name: str):
        """Hot-reload a plugin without restarting."""
        if name in self._plugins:
            path = self._plugins[name].path
            folder = os.path.basename(os.path.dirname(path))
            del self._plugins[name]
            self._load_plugin(name, path, folder)
            if self.log:
                self.log.success(f"[Plugin] Reloaded: {name}")
    def get_plugins(self) -> dict:
        """Return plugin-dir plugins as {name: class}."""
        return {n: m.cls for n,m in self._plugins.items() if n.startswith("plugin_") and m.cls}

    def get_metadata_all(self) -> list:
        result = []
        for name, meta in self._plugins.items():
            entry = {"name": name, "path": meta.path, "enabled": meta.enabled}
            if meta.cls and hasattr(meta.cls, "get_metadata"):
                try: entry.update(meta.cls.get_metadata())
                except Exception as _e:
                    from core.error_handler import get_handler
                    get_handler().capture("plugin_loader", _e)
            result.append(entry)
        return result

