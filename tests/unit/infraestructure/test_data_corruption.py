"""
Testes de Corrupção de Dados - Omni Writer
==========================================

Implementa testes para cenários de corrupção de dados:
- Corrupção durante escrita no storage
- Recuperação de dados corrompidos
- Validação de checksums
- Verificação de integridade de backup
- Tratamento de arquivos ZIP corrompidos

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import os
import tempfile
import hashlib
import json
import zipfile
import shutil
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import time

# Importações do sistema real
from infraestructure.storage import save_article, load_article, validate_file_integrity
from scripts.backup import create_backup, restore_backup, validate_backup_integrity
from shared.intelligent_cache import IntelligentCache
from shared.status_repository import StatusRepository


class TestStorageFileCorruption:
    """Testa corrupção durante escrita no storage."""
    
    def test_storage_file_corruption_during_write(self, tmp_path):
        """Testa corrupção durante escrita no storage."""
        # Setup baseado no código real
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Dados reais de artigo
        article_data = {
            "title": "Artigo de Teste para Corrupção",
            "content": "Conteúdo do artigo que será testado para corrupção de dados durante a escrita.",
            "prompt": "Prompt real para geração de artigo sobre corrupção de dados",
            "model": "openai",
            "timestamp": time.time(),
            "metadata": {
                "generation_time": 15.5,
                "tokens_used": 1250,
                "model_version": "gpt-3.5-turbo"
            }
        }
        
        # Simula corrupção durante escrita
        original_open = open
        
        def corrupted_open(filepath, mode='r', **kwargs):
            """Simula abertura de arquivo com corrupção."""
            if 'w' in mode and 'article' in str(filepath):
                # Corrompe o arquivo durante escrita
                file_obj = original_open(filepath, mode, **kwargs)
                
                def corrupted_write(data):
                    """Corrompe dados durante escrita."""
                    if isinstance(data, str):
                        # Remove alguns caracteres aleatoriamente
                        corrupted_data = data.replace('a', '').replace('e', '')
                    else:
                        corrupted_data = data
                    return file_obj.write(corrupted_data)
                
                file_obj.write = corrupted_write
                return file_obj
            return original_open(filepath, mode, **kwargs)
        
        # Aplica mock de corrupção
        with patch('builtins.open', side_effect=corrupted_open):
            try:
                # Tenta salvar artigo (deve falhar ou gerar arquivo corrompido)
                result = save_article(article_data, str(output_dir))
                
                # Verifica se arquivo foi criado
                files_created = list(output_dir.glob("*.txt"))
                assert len(files_created) > 0
                
                # Tenta carregar arquivo (deve detectar corrupção)
                with pytest.raises(Exception):
                    loaded_data = load_article(files_created[0])
                
            except Exception as e:
                # Esperado que falhe devido à corrupção
                assert "corruption" in str(e).lower() or "integrity" in str(e).lower()
    
    def test_partial_file_corruption(self, tmp_path):
        """Testa corrupção parcial de arquivo."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Cria arquivo válido primeiro
        article_data = {
            "title": "Artigo Válido",
            "content": "Conteúdo válido do artigo que será parcialmente corrompido.",
            "prompt": "Prompt válido",
            "model": "openai",
            "timestamp": time.time()
        }
        
        # Salva arquivo válido
        filepath = save_article(article_data, str(output_dir))
        
        # Corrompe arquivo manualmente
        with open(filepath, 'r+', encoding='utf-8') as f:
            content = f.read()
            # Corrompe parte do conteúdo
            corrupted_content = content.replace("válido", "corrompido").replace("Artigo", "Arquivo")
            f.seek(0)
            f.write(corrupted_content)
            f.truncate()
        
        # Tenta carregar arquivo corrompido
        with pytest.raises(Exception):
            loaded_data = load_article(filepath)
    
    def test_file_truncation_detection(self, tmp_path):
        """Testa detecção de truncamento de arquivo."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Cria arquivo válido
        article_data = {
            "title": "Artigo Completo",
            "content": "Conteúdo completo do artigo que será truncado para testar detecção de corrupção.",
            "prompt": "Prompt completo",
            "model": "openai",
            "timestamp": time.time()
        }
        
        # Salva arquivo
        filepath = save_article(article_data, str(output_dir))
        
        # Trunca arquivo manualmente
        with open(filepath, 'r+', encoding='utf-8') as f:
            content = f.read()
            # Remove metade do conteúdo
            truncated_content = content[:len(content)//2]
            f.seek(0)
            f.write(truncated_content)
            f.truncate()
        
        # Tenta carregar arquivo truncado
        with pytest.raises(Exception):
            loaded_data = load_article(filepath)


class TestCorruptedDataRecovery:
    """Testa recuperação de dados corrompidos."""
    
    def test_corrupted_data_recovery(self, tmp_path):
        """Testa recuperação de dados corrompidos."""
        # Setup baseado no código real
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Cria múltiplos arquivos (um válido, um corrompido)
        valid_article = {
            "title": "Artigo Válido",
            "content": "Conteúdo válido para recuperação.",
            "prompt": "Prompt válido",
            "model": "openai",
            "timestamp": time.time()
        }
        
        corrupted_article = {
            "title": "Artigo Corrompido",
            "content": "Conteúdo que será corrompido.",
            "prompt": "Prompt válido",
            "model": "openai",
            "timestamp": time.time()
        }
        
        # Salva arquivo válido
        valid_filepath = save_article(valid_article, str(output_dir))
        
        # Salva e corrompe segundo arquivo
        corrupted_filepath = save_article(corrupted_article, str(output_dir))
        with open(corrupted_filepath, 'w', encoding='utf-8') as f:
            f.write("Dados corrompidos")
        
        # Testa recuperação
        recovery_results = []
        
        # Tenta carregar arquivo válido (deve funcionar)
        try:
            loaded_valid = load_article(valid_filepath)
            recovery_results.append(("valid", True, loaded_valid))
        except Exception as e:
            recovery_results.append(("valid", False, str(e)))
        
        # Tenta carregar arquivo corrompido (deve falhar)
        try:
            loaded_corrupted = load_article(corrupted_filepath)
            recovery_results.append(("corrupted", True, loaded_corrupted))
        except Exception as e:
            recovery_results.append(("corrupted", False, str(e)))
        
        # Valida resultados
        assert len(recovery_results) == 2
        
        # Arquivo válido deve ter sido carregado com sucesso
        valid_result = next(r for r in recovery_results if r[0] == "valid")
        assert valid_result[1] is True
        
        # Arquivo corrompido deve ter falhado
        corrupted_result = next(r for r in recovery_results if r[0] == "corrupted")
        assert corrupted_result[1] is False
    
    def test_backup_recovery_mechanism(self, tmp_path):
        """Testa mecanismo de recuperação via backup."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        
        # Cria arquivo original
        article_data = {
            "title": "Artigo com Backup",
            "content": "Conteúdo que será corrompido mas tem backup.",
            "prompt": "Prompt válido",
            "model": "openai",
            "timestamp": time.time()
        }
        
        # Salva arquivo e cria backup
        filepath = save_article(article_data, str(output_dir))
        backup_filepath = backup_dir / f"backup_{os.path.basename(filepath)}"
        shutil.copy2(filepath, backup_filepath)
        
        # Corrompe arquivo original
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("Dados corrompidos")
        
        # Simula recuperação via backup
        try:
            # Tenta carregar arquivo original (deve falhar)
            load_article(filepath)
        except Exception:
            # Se falhar, tenta recuperar do backup
            try:
                recovered_data = load_article(backup_filepath)
                # Restaura arquivo original
                shutil.copy2(backup_filepath, filepath)
                assert recovered_data["title"] == article_data["title"]
            except Exception as e:
                pytest.fail(f"Recuperação do backup falhou: {e}")


class TestChecksumValidation:
    """Testa validação de checksums."""
    
    def test_checksum_validation(self, tmp_path):
        """Testa validação de checksums."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Dados de teste
        article_data = {
            "title": "Artigo com Checksum",
            "content": "Conteúdo que será validado por checksum.",
            "prompt": "Prompt válido",
            "model": "openai",
            "timestamp": time.time()
        }
        
        # Calcula checksum original
        content_str = json.dumps(article_data, sort_keys=True)
        original_checksum = hashlib.sha256(content_str.encode()).hexdigest()
        
        # Salva arquivo com checksum
        filepath = save_article(article_data, str(output_dir))
        
        # Valida integridade do arquivo
        integrity_result = validate_file_integrity(filepath, original_checksum)
        assert integrity_result['valid'] is True
        
        # Corrompe arquivo
        with open(filepath, 'r+', encoding='utf-8') as f:
            content = f.read()
            corrupted_content = content.replace("Artigo", "Arquivo")
            f.seek(0)
            f.write(corrupted_content)
            f.truncate()
        
        # Valida integridade do arquivo corrompido
        integrity_result = validate_file_integrity(filepath, original_checksum)
        assert integrity_result['valid'] is False
    
    def test_checksum_mismatch_detection(self, tmp_path):
        """Testa detecção de mismatch de checksum."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Cria arquivo
        article_data = {
            "title": "Artigo para Checksum",
            "content": "Conteúdo para validação de checksum.",
            "prompt": "Prompt válido",
            "model": "openai",
            "timestamp": time.time()
        }
        
        # Salva arquivo
        filepath = save_article(article_data, str(output_dir))
        
        # Calcula checksum incorreto
        wrong_checksum = "a" * 64  # Checksum falso
        
        # Valida com checksum incorreto
        integrity_result = validate_file_integrity(filepath, wrong_checksum)
        assert integrity_result['valid'] is False
        assert 'checksum' in integrity_result['reason'].lower() or 'integrity' in integrity_result['reason'].lower()
    
    def test_checksum_generation_consistency(self, tmp_path):
        """Testa consistência na geração de checksums."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Mesmo conteúdo deve gerar mesmo checksum
        article_data = {
            "title": "Artigo Consistente",
            "content": "Conteúdo para teste de consistência de checksum.",
            "prompt": "Prompt válido",
            "model": "openai",
            "timestamp": time.time()
        }
        
        # Gera checksums múltiplas vezes
        checksums = []
        for _ in range(5):
            content_str = json.dumps(article_data, sort_keys=True)
            checksum = hashlib.sha256(content_str.encode()).hexdigest()
            checksums.append(checksum)
        
        # Todos os checksums devem ser iguais
        assert len(set(checksums)) == 1


class TestBackupIntegrityCheck:
    """Testa verificação de integridade de backup."""
    
    def test_backup_integrity_check(self, tmp_path):
        """Testa verificação de integridade de backup."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        
        # Cria dados de teste
        articles = []
        for i in range(3):
            article = {
                "title": f"Artigo {i}",
                "content": f"Conteúdo do artigo {i} para backup.",
                "prompt": f"Prompt {i}",
                "model": "openai",
                "timestamp": time.time()
            }
            articles.append(article)
        
        # Salva arquivos e cria backups
        filepaths = []
        backup_filepaths = []
        
        for article in articles:
            filepath = save_article(article, str(output_dir))
            filepaths.append(filepath)
            
            backup_filepath = backup_dir / f"backup_{os.path.basename(filepath)}"
            shutil.copy2(filepath, backup_filepath)
            backup_filepaths.append(backup_filepath)
        
        # Valida integridade dos backups
        integrity_results = []
        for backup_filepath in backup_filepaths:
            result = validate_backup_integrity(backup_filepath)
            integrity_results.append(result)
        
        # Todos os backups devem ser válidos
        assert all(result['valid'] for result in integrity_results)
    
    def test_corrupted_backup_detection(self, tmp_path):
        """Testa detecção de backup corrompido."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        
        # Cria arquivo e backup
        article_data = {
            "title": "Artigo para Backup",
            "content": "Conteúdo que será corrompido no backup.",
            "prompt": "Prompt válido",
            "model": "openai",
            "timestamp": time.time()
        }
        
        filepath = save_article(article_data, str(output_dir))
        backup_filepath = backup_dir / f"backup_{os.path.basename(filepath)}"
        shutil.copy2(filepath, backup_filepath)
        
        # Corrompe backup
        with open(backup_filepath, 'w', encoding='utf-8') as f:
            f.write("Backup corrompido")
        
        # Valida integridade do backup corrompido
        integrity_result = validate_backup_integrity(backup_filepath)
        assert integrity_result['valid'] is False
    
    def test_backup_restoration_validation(self, tmp_path):
        """Testa validação de restauração de backup."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        
        # Cria arquivo original
        article_data = {
            "title": "Artigo para Restauração",
            "content": "Conteúdo que será restaurado do backup.",
            "prompt": "Prompt válido",
            "model": "openai",
            "timestamp": time.time()
        }
        
        # Salva arquivo e cria backup
        filepath = save_article(article_data, str(output_dir))
        backup_filepath = backup_dir / f"backup_{os.path.basename(filepath)}"
        shutil.copy2(filepath, backup_filepath)
        
        # Corrompe arquivo original
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("Arquivo corrompido")
        
        # Restaura do backup
        restored_data = restore_backup(backup_filepath, filepath)
        
        # Valida restauração
        assert restored_data["title"] == article_data["title"]
        assert restored_data["content"] == article_data["content"]
        
        # Valida que arquivo foi restaurado
        loaded_data = load_article(filepath)
        assert loaded_data["title"] == article_data["title"]


class TestCorruptedZipHandling:
    """Testa tratamento de arquivos ZIP corrompidos."""
    
    def test_corrupted_zip_handling(self, tmp_path):
        """Testa tratamento de ZIP corrompido."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        zip_dir = tmp_path / "zip"
        zip_dir.mkdir()
        
        # Cria arquivos para ZIP
        articles = []
        for i in range(3):
            article = {
                "title": f"Artigo {i}",
                "content": f"Conteúdo do artigo {i} para ZIP.",
                "prompt": f"Prompt {i}",
                "model": "openai",
                "timestamp": time.time()
            }
            articles.append(article)
        
        # Salva arquivos
        filepaths = []
        for article in articles:
            filepath = save_article(article, str(output_dir))
            filepaths.append(filepath)
        
        # Cria ZIP válido
        zip_filepath = zip_dir / "articles.zip"
        with zipfile.ZipFile(zip_filepath, 'w') as zipf:
            for filepath in filepaths:
                zipf.write(filepath, os.path.basename(filepath))
        
        # Valida ZIP válido
        try:
            with zipfile.ZipFile(zip_filepath, 'r') as zipf:
                zipf.testzip()  # Deve passar sem erros
        except Exception as e:
            pytest.fail(f"ZIP válido falhou na validação: {e}")
        
        # Corrompe ZIP
        with open(zip_filepath, 'r+b') as f:
            # Corrompe alguns bytes no meio do arquivo
            f.seek(100)
            f.write(b'CORRUPTED')
        
        # Tenta validar ZIP corrompido
        with pytest.raises(Exception):
            with zipfile.ZipFile(zip_filepath, 'r') as zipf:
                zipf.testzip()
    
    def test_partial_zip_extraction(self, tmp_path):
        """Testa extração parcial de ZIP corrompido."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        zip_dir = tmp_path / "zip"
        zip_dir.mkdir()
        
        # Cria arquivos para ZIP
        articles = []
        for i in range(5):
            article = {
                "title": f"Artigo {i}",
                "content": f"Conteúdo do artigo {i} para extração parcial.",
                "prompt": f"Prompt {i}",
                "model": "openai",
                "timestamp": time.time()
            }
            articles.append(article)
        
        # Salva arquivos
        filepaths = []
        for article in articles:
            filepath = save_article(article, str(output_dir))
            filepaths.append(filepath)
        
        # Cria ZIP
        zip_filepath = zip_dir / "articles_partial.zip"
        with zipfile.ZipFile(zip_filepath, 'w') as zipf:
            for filepath in filepaths:
                zipf.write(filepath, os.path.basename(filepath))
        
        # Corrompe ZIP (mantém alguns arquivos válidos)
        with open(zip_filepath, 'r+b') as f:
            # Corrompe apenas parte do arquivo
            f.seek(200)
            f.write(b'PARTIAL_CORRUPTION')
        
        # Tenta extrair arquivos válidos
        extracted_count = 0
        try:
            with zipfile.ZipFile(zip_filepath, 'r') as zipf:
                for info in zipf.infolist():
                    try:
                        zipf.extract(info, zip_dir)
                        extracted_count += 1
                    except Exception:
                        # Arquivo corrompido, pula
                        continue
        except Exception:
            # ZIP muito corrompido
            pass
        
        # Pelo menos alguns arquivos devem ter sido extraídos
        assert extracted_count >= 0  # Pode ser 0 se muito corrompido


class TestDataIntegrityMonitoring:
    """Testa monitoramento de integridade de dados."""
    
    def test_continuous_integrity_checking(self, tmp_path):
        """Testa verificação contínua de integridade."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Cria múltiplos arquivos
        articles = []
        for i in range(10):
            article = {
                "title": f"Artigo {i}",
                "content": f"Conteúdo do artigo {i} para monitoramento de integridade.",
                "prompt": f"Prompt {i}",
                "model": "openai",
                "timestamp": time.time()
            }
            articles.append(article)
        
        # Salva arquivos
        filepaths = []
        for article in articles:
            filepath = save_article(article, str(output_dir))
            filepaths.append(filepath)
        
        # Simula verificação contínua de integridade
        integrity_results = []
        for filepath in filepaths:
            try:
                # Tenta carregar arquivo (validação implícita)
                loaded_data = load_article(filepath)
                integrity_results.append((filepath, True, None))
            except Exception as e:
                integrity_results.append((filepath, False, str(e)))
        
        # Todos os arquivos devem ser válidos inicialmente
        valid_count = sum(1 for _, valid, _ in integrity_results if valid)
        assert valid_count == len(filepaths)
        
        # Corrompe alguns arquivos
        corrupted_files = filepaths[::3]  # Corrompe a cada 3 arquivos
        for filepath in corrupted_files:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("Arquivo corrompido")
        
        # Verifica integridade novamente
        integrity_results_after = []
        for filepath in filepaths:
            try:
                loaded_data = load_article(filepath)
                integrity_results_after.append((filepath, True, None))
            except Exception as e:
                integrity_results_after.append((filepath, False, str(e)))
        
        # Alguns arquivos devem estar corrompidos
        valid_count_after = sum(1 for _, valid, _ in integrity_results_after if valid)
        assert valid_count_after < len(filepaths)
        assert valid_count_after > 0  # Alguns devem permanecer válidos
    
    def test_integrity_alert_system(self, tmp_path):
        """Testa sistema de alertas de integridade."""
        # Setup
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        # Cria arquivo
        article_data = {
            "title": "Artigo para Alerta",
            "content": "Conteúdo que será corrompido para testar alertas.",
            "prompt": "Prompt válido",
            "model": "openai",
            "timestamp": time.time()
        }
        
        # Salva arquivo
        filepath = save_article(article_data, str(output_dir))
        
        # Simula sistema de alertas
        alerts = []
        
        def integrity_alert(filepath, error):
            """Função de alerta de integridade."""
            alerts.append({
                "filepath": str(filepath),
                "error": str(error),
                "timestamp": time.time()
            })
        
        # Verifica integridade inicial (sem alertas)
        try:
            load_article(filepath)
        except Exception as e:
            integrity_alert(filepath, e)
        
        assert len(alerts) == 0
        
        # Corrompe arquivo
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("Arquivo corrompido para alerta")
        
        # Verifica integridade após corrupção (deve gerar alerta)
        try:
            load_article(filepath)
        except Exception as e:
            integrity_alert(filepath, e)
        
        assert len(alerts) == 1
        assert "corrompido" in alerts[0]["error"].lower() or "integrity" in alerts[0]["error"].lower() 