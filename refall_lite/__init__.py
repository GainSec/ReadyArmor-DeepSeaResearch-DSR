"""REFALL Lite: bounded campaign state for the Firmware Spider project.

Canonical state lives in the ArcticBase REFALL state layer (Lite subset).
"""
from .arcticbase.contracts import LAYER_NAME, PROFILE, STAGES
from .service import RefallLite

__version__ = "0.2.0"
__all__ = ["RefallLite", "LAYER_NAME", "PROFILE", "STAGES", "__version__"]
