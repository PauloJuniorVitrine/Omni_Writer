"""
Integration Module - Omni Writer Load Tests
==========================================

Módulo de integração com sistemas de monitoramento existentes.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 3, Item 20
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T16:40:00Z
"""

from .monitoring_integration import (
    MonitoringIntegration,
    MonitoringConfig,
    CustomMetric,
    DashboardConfig,
    UnifiedAlert
)

__version__ = "1.0.0"
__author__ = "Omni Writer Team"
__description__ = "Sistema de integração com monitoramento existente"

__all__ = [
    "MonitoringIntegration",
    "MonitoringConfig", 
    "CustomMetric",
    "DashboardConfig",
    "UnifiedAlert"
] 