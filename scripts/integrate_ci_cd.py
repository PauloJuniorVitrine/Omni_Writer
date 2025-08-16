#!/usr/bin/env python3
"""
Integração CI/CD Completa - Omni Writer
Tracing ID: CI_CD_INTEGRATION_20250127_001

Este script integra validação de contratos e geração de SDKs
em um pipeline completo de CI/CD.
"""

import json
import yaml
import os
import sys
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger(__name__)

@dataclass
class IntegrationStep:
    """Etapa de integração"""
    name: str
    status: str
    duration: float
    output: str
    errors: List[str]
    warnings: List[str]

class CICDIntegrator:
    """Integrador de CI/CD para validação e geração"""
    
    def __init__(self, config_path: str = "ci_cd_config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.steps: List[IntegrationStep] = []
        self.start_time = time.time()
        
    def _load_config(self) -> Dict[str, Any]:
        """Carrega configuração do CI/CD"""
        default_config = {
            "openapi_path": "docs/openapi.yaml",
            "api_base_url": "http://localhost:5000",
            "output_dir": "generated_sdks",
            "reports_dir": "ci_cd_reports",
            "steps": [
                "validate_contracts",
                "generate_sdks",
                "run_tests",
                "generate_docs"
            ],
            "notifications": {
                "slack_webhook": None,
                "email": None
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    default_config.update(config)
            except Exception as e:
                logger.warning(f"Erro ao carregar configuração: {e}")
        
        return default_config
    
    def run_step(self, step_name: str) -> IntegrationStep:
        """Executa uma etapa específica"""
        start_time = time.time()
        step = IntegrationStep(
            name=step_name,
            status="RUNNING",
            duration=0.0,
            output="",
            errors=[],
            warnings=[]
        )
        
        logger.info(f"Executando etapa: {step_name}")
        
        try:
            if step_name == "validate_contracts":
                result = self._run_contract_validation()
            elif step_name == "generate_sdks":
                result = self._run_sdk_generation()
            elif step_name == "run_tests":
                result = self._run_tests()
            elif step_name == "generate_docs":
                result = self._run_docs_generation()
            else:
                result = {"status": "SKIPPED", "output": "Etapa não implementada"}
            
            step.status = result.get("status", "UNKNOWN")
            step.output = result.get("output", "")
            step.errors = result.get("errors", [])
            step.warnings = result.get("warnings", [])
            
        except Exception as e:
            step.status = "FAILED"
            step.errors.append(str(e))
            logger.error(f"Erro na etapa {step_name}: {e}")
        
        step.duration = time.time() - start_time
        self.steps.append(step)
        
        logger.info(f"Etapa {step_name} concluída: {step.status} ({step.duration:.2f}s)")
        return step
    
    def _run_contract_validation(self) -> Dict[str, Any]:
        """Executa validação de contratos"""
        try:
            cmd = [sys.executable, "scripts/validate_contracts.py"]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env={**os.environ, "API_BASE_URL": self.config["api_base_url"]}
            )
            
            output = process.stdout
            errors = []
            warnings = []
            
            if process.returncode != 0:
                errors.append(process.stderr)
                status = "FAILED"
            else:
                status = "SUCCESS"
            
            # Tenta carregar relatório
            report_path = "contract_validation_report.json"
            if Path(report_path).exists():
                try:
                    with open(report_path, 'r') as f:
                        report = json.load(f)
                        summary = report.get("summary", {})
                        if summary.get("failed", 0) > 0:
                            status = "FAILED"
                        elif summary.get("warnings", 0) > 0:
                            warnings.append(f"{summary.get('warnings', 0)} avisos encontrados")
                except Exception as e:
                    warnings.append(f"Erro ao ler relatório: {e}")
            
            return {
                "status": status,
                "output": output,
                "errors": errors,
                "warnings": warnings
            }
            
        except Exception as e:
            return {
                "status": "FAILED",
                "output": "",
                "errors": [str(e)],
                "warnings": []
            }
    
    def _run_sdk_generation(self) -> Dict[str, Any]:
        """Executa geração de SDKs"""
        try:
            cmd = [sys.executable, "scripts/generate_sdks.py"]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            output = process.stdout
            errors = []
            warnings = []
            
            if process.returncode != 0:
                errors.append(process.stderr)
                status = "FAILED"
            else:
                status = "SUCCESS"
            
            # Tenta carregar relatório
            report_path = "sdk_generation_report.json"
            if Path(report_path).exists():
                try:
                    with open(report_path, 'r') as f:
                        report = json.load(f)
                        summary = report.get("summary", {})
                        if summary.get("failed", 0) > 0:
                            status = "FAILED"
                        elif summary.get("warnings", 0) > 0:
                            warnings.append(f"{summary.get('warnings', 0)} avisos encontrados")
                except Exception as e:
                    warnings.append(f"Erro ao ler relatório: {e}")
            
            return {
                "status": status,
                "output": output,
                "errors": errors,
                "warnings": warnings
            }
            
        except Exception as e:
            return {
                "status": "FAILED",
                "output": "",
                "errors": [str(e)],
                "warnings": []
            }
    
    def _run_tests(self) -> Dict[str, Any]:
        """Executa testes automatizados"""
        try:
            # Executa testes unitários
            cmd = [sys.executable, "-m", "pytest", "tests/unit/", "-v", "--tb=short"]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            output = process.stdout
            errors = []
            warnings = []
            
            if process.returncode != 0:
                errors.append(process.stderr)
                status = "FAILED"
            else:
                status = "SUCCESS"
            
            return {
                "status": status,
                "output": output,
                "errors": errors,
                "warnings": warnings
            }
            
        except Exception as e:
            return {
                "status": "FAILED",
                "output": "",
                "errors": [str(e)],
                "warnings": []
            }
    
    def _run_docs_generation(self) -> Dict[str, Any]:
        """Executa geração de documentação"""
        try:
            # Gera documentação da API
            cmd = [sys.executable, "-m", "flask", "openapi", "generate"]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd="app"
            )
            
            output = process.stdout
            errors = []
            warnings = []
            
            if process.returncode != 0:
                errors.append(process.stderr)
                status = "FAILED"
            else:
                status = "SUCCESS"
            
            return {
                "status": status,
                "output": output,
                "errors": errors,
                "warnings": warnings
            }
            
        except Exception as e:
            return {
                "status": "FAILED",
                "output": "",
                "errors": [str(e)],
                "warnings": []
            }
    
    def run_pipeline(self) -> bool:
        """Executa pipeline completo de CI/CD"""
        logger.info("Iniciando pipeline de CI/CD...")
        
        steps_to_run = self.config.get("steps", [])
        success = True
        
        for step_name in steps_to_run:
            step = self.run_step(step_name)
            
            if step.status == "FAILED":
                success = False
                logger.error(f"Etapa {step_name} falhou")
                
                # Opcional: para pipeline em caso de falha crítica
                if step_name in ["validate_contracts"]:
                    logger.error("Pipeline interrompido devido a falha crítica")
                    break
        
        total_duration = time.time() - self.start_time
        logger.info(f"Pipeline concluído em {total_duration:.2f}s")
        
        # Gera relatório final
        self._generate_final_report(success, total_duration)
        
        return success
    
    def _generate_final_report(self, success: bool, total_duration: float):
        """Gera relatório final do pipeline"""
        reports_dir = Path(self.config["reports_dir"])
        reports_dir.mkdir(exist_ok=True)
        
        # Estatísticas
        total_steps = len(self.steps)
        successful_steps = len([s for s in self.steps if s.status == "SUCCESS"])
        failed_steps = len([s for s in self.steps if s.status == "FAILED"])
        skipped_steps = len([s for s in self.steps if s.status == "SKIPPED"])
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "tracing_id": "CI_CD_INTEGRATION_20250127_001",
            "pipeline_status": "SUCCESS" if success else "FAILED",
            "total_duration": total_duration,
            "summary": {
                "total_steps": total_steps,
                "successful": successful_steps,
                "failed": failed_steps,
                "skipped": skipped_steps,
                "success_rate": (successful_steps / total_steps * 100) if total_steps > 0 else 0
            },
            "steps": [
                {
                    "name": step.name,
                    "status": step.status,
                    "duration": step.duration,
                    "errors": step.errors,
                    "warnings": step.warnings
                }
                for step in self.steps
            ],
            "config": self.config
        }
        
        # Salva relatório
        report_path = reports_dir / f"pipeline_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Relatório salvo: {report_path}")
        
        # Exibe resumo
        logger.info("=== RESUMO DO PIPELINE ===")
        logger.info(f"Status: {'✅ SUCESSO' if success else '❌ FALHA'}")
        logger.info(f"Duração total: {total_duration:.2f}s")
        logger.info(f"Etapas: {successful_steps}/{total_steps} bem-sucedidas")
        logger.info(f"Taxa de sucesso: {report['summary']['success_rate']:.1f}%")
        
        # Exibe detalhes das etapas
        for step in self.steps:
            status_icon = "✅" if step.status == "SUCCESS" else "❌" if step.status == "FAILED" else "⏭️"
            logger.info(f"  {status_icon} {step.name}: {step.status} ({step.duration:.2f}s)")
            if step.errors:
                for error in step.errors:
                    logger.error(f"    - Erro: {error}")
            if step.warnings:
                for warning in step.warnings:
                    logger.warning(f"    - Aviso: {warning}")
    
    def send_notifications(self, success: bool):
        """Envia notificações sobre o resultado do pipeline"""
        notifications = self.config.get("notifications", {})
        
        # Slack notification
        slack_webhook = notifications.get("slack_webhook")
        if slack_webhook:
            self._send_slack_notification(slack_webhook, success)
        
        # Email notification
        email = notifications.get("email")
        if email:
            self._send_email_notification(email, success)
    
    def _send_slack_notification(self, webhook_url: str, success: bool):
        """Envia notificação para Slack"""
        try:
            import requests
            
            status_icon = "✅" if success else "❌"
            status_text = "SUCESSO" if success else "FALHA"
            
            message = {
                "text": f"{status_icon} Pipeline CI/CD - {status_text}",
                "attachments": [
                    {
                        "color": "good" if success else "danger",
                        "fields": [
                            {
                                "title": "Status",
                                "value": status_text,
                                "short": True
                            },
                            {
                                "title": "Duração",
                                "value": f"{time.time() - self.start_time:.2f}s",
                                "short": True
                            },
                            {
                                "title": "Etapas",
                                "value": f"{len([s for s in self.steps if s.status == 'SUCCESS'])}/{len(self.steps)}",
                                "short": True
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=message)
            if response.status_code == 200:
                logger.info("Notificação Slack enviada")
            else:
                logger.warning(f"Erro ao enviar notificação Slack: {response.status_code}")
                
        except Exception as e:
            logger.warning(f"Erro ao enviar notificação Slack: {e}")
    
    def _send_email_notification(self, email: str, success: bool):
        """Envia notificação por email"""
        # Implementação básica - pode ser expandida
        logger.info(f"Notificação por email seria enviada para: {email}")
        logger.info(f"Status: {'SUCCESS' if success else 'FAILED'}")

def main():
    """Função principal"""
    # Configuração
    config_path = os.getenv("CI_CD_CONFIG", "ci_cd_config.yaml")
    
    # Execução
    integrator = CICDIntegrator(config_path)
    
    try:
        success = integrator.run_pipeline()
        
        # Envia notificações
        integrator.send_notifications(success)
        
        # Exit code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        logger.info("Pipeline interrompido pelo usuário")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erro fatal no pipeline: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 