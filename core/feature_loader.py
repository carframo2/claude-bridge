import importlib
import pkgutil
import features
from flask import Flask

def register_all_features(app: Flask) -> None:
    for _, module_name, _ in pkgutil.iter_modules(features.__path__):
        mod = importlib.import_module(f"{features.__name__}.{module_name}")

        # Opción A: el módulo expone `register(app)`
        register = getattr(mod, "register", None)
        if callable(register):
            register(app)
            continue

        # Opción B: el módulo expone `bp` (Blueprint)
        bp = getattr(mod, "bp", None)
        if bp is not None:
            app.register_blueprint(bp)
