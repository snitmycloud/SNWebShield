"""Registers the built-in IDENTIFY engines. Later engines (Nuclei) register the same way and need no other change."""
from app.services import engines


def register_builtin() -> None:
    from app.services.engine_config import ConfigurationEngine
    from app.services.engine_eol import LifecycleEngine
    from app.services.engine_nuclei import NucleiEngine
    from app.services.engine_vulns import VulnerabilityEngine
    have = {e.name for e in engines.registered()}
    for engine in (ConfigurationEngine(), VulnerabilityEngine(), LifecycleEngine(), NucleiEngine()):
        if engine.name not in have:
            engines.register(engine)
