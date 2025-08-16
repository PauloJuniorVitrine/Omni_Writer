#!/usr/bin/env python3
"""
Script de gerenciamento de traduções para Omni Writer.
Automatiza processos de internacionalização e manutenção de traduções.
"""

import os
import json
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime
import logging

# Adiciona o diretório raiz ao path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.dynamic_i18n import DynamicI18n

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('manage_translations')


class TranslationManager:
    """
    Gerenciador de traduções para automatizar processos de i18n.
    """
    
    def __init__(self, i18n_dir: str = "shared/i18n"):
        self.i18n_dir = Path(i18n_dir)
        self.i18n = DynamicI18n(str(self.i18n_dir))
        
    def scan_missing_translations(self) -> Dict[str, List[str]]:
        """
        Escaneia traduções faltantes em todos os idiomas.
        
        Returns:
            Dicionário com idioma -> lista de chaves faltantes
        """
        logger.info("Escaneando traduções faltantes...")
        
        # Obtém todas as chaves do idioma de referência (português)
        reference_lang = "pt_BR"
        reference_keys = set(self.i18n.translations.get(reference_lang, {}).keys())
        
        missing_translations = {}
        
        for lang_code in self.i18n.supported_languages:
            if lang_code == reference_lang:
                continue
                
            current_keys = set(self.i18n.translations.get(lang_code, {}).keys())
            missing_keys = reference_keys - current_keys
            
            if missing_keys:
                missing_translations[lang_code] = sorted(list(missing_keys))
                logger.info(f"{lang_code}: {len(missing_keys)} traduções faltantes")
        
        return missing_translations
    
    def generate_translation_template(self, lang_code: str) -> str:
        """
        Gera template de tradução para um idioma.
        
        Args:
            lang_code: Código do idioma
        
        Returns:
            Template JSON formatado
        """
        logger.info(f"Gerando template para {lang_code}...")
        
        reference_lang = "pt_BR"
        reference_translations = self.i18n.translations.get(reference_lang, {})
        
        template = {}
        for key, value in reference_translations.items():
            # Adiciona comentário indicando que precisa tradução
            template[key] = f"TODO: {value}"
        
        return json.dumps(template, indent=2, ensure_ascii=False)
    
    def validate_translations(self) -> Dict[str, List[str]]:
        """
        Valida traduções existentes.
        
        Returns:
            Dicionário com idioma -> lista de problemas encontrados
        """
        logger.info("Validando traduções...")
        
        issues = {}
        
        for lang_code, translations in self.i18n.translations.items():
            lang_issues = []
            
            for key, value in translations.items():
                # Verifica se há placeholders não traduzidos
                if "TODO:" in value:
                    lang_issues.append(f"Tradução pendente: {key}")
                
                # Verifica se há variáveis não interpoladas
                if "{" in value and "}" in value:
                    # Verifica se são variáveis válidas (não traduções pendentes)
                    if not any(todo in value for todo in ["TODO:", "FIXME:", "TRANSLATE:"]):
                        # Verifica se as variáveis estão balanceadas
                        open_braces = value.count("{")
                        close_braces = value.count("}")
                        if open_braces != close_braces:
                            lang_issues.append(f"Variáveis desbalanceadas em {key}: {value}")
            
            if lang_issues:
                issues[lang_code] = lang_issues
                logger.warning(f"{lang_code}: {len(lang_issues)} problemas encontrados")
        
        return issues
    
    def export_translations_report(self, output_file: str = "translation_report.json"):
        """
        Exporta relatório completo de traduções.
        
        Args:
            output_file: Arquivo de saída
        """
        logger.info(f"Gerando relatório: {output_file}")
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "total_languages": len(self.i18n.supported_languages),
            "supported_languages": list(self.i18n.supported_languages.keys()),
            "missing_translations": self.scan_missing_translations(),
            "validation_issues": self.validate_translations(),
            "statistics": {}
        }
        
        # Estatísticas por idioma
        for lang_code in self.i18n.supported_languages:
            translations = self.i18n.translations.get(lang_code, {})
            total_keys = len(translations)
            
            # Conta traduções pendentes
            pending_count = sum(1 for value in translations.values() if "TODO:" in value)
            
            # Conta traduções completas
            complete_count = total_keys - pending_count
            
            report["statistics"][lang_code] = {
                "total_keys": total_keys,
                "complete_translations": complete_count,
                "pending_translations": pending_count,
                "completion_percentage": round((complete_count / total_keys * 100), 2) if total_keys > 0 else 0
            }
        
        # Salva relatório
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Relatório salvo em: {output_file}")
        return report
    
    def create_missing_translation_files(self, output_dir: str = "missing_translations"):
        """
        Cria arquivos com traduções faltantes para facilitar tradução.
        
        Args:
            output_dir: Diretório de saída
        """
        logger.info(f"Criando arquivos de traduções faltantes em: {output_dir}")
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        missing_translations = self.scan_missing_translations()
        
        for lang_code, missing_keys in missing_translations.items():
            if not missing_keys:
                continue
            
            # Obtém traduções de referência
            reference_translations = self.i18n.translations.get("pt_BR", {})
            
            # Cria arquivo com traduções faltantes
            missing_file = output_path / f"{lang_code}_missing.json"
            
            missing_data = {}
            for key in missing_keys:
                if key in reference_translations:
                    missing_data[key] = f"TODO: {reference_translations[key]}"
            
            with open(missing_file, 'w', encoding='utf-8') as f:
                json.dump(missing_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Arquivo criado: {missing_file} ({len(missing_keys)} chaves)")
    
    def merge_translations(self, source_file: str, target_lang: str):
        """
        Mescla traduções de um arquivo para o idioma de destino.
        
        Args:
            source_file: Arquivo com traduções
            target_lang: Idioma de destino
        """
        logger.info(f"Mesclando traduções de {source_file} para {target_lang}...")
        
        if not os.path.exists(source_file):
            logger.error(f"Arquivo não encontrado: {source_file}")
            return False
        
        try:
            with open(source_file, 'r', encoding='utf-8') as f:
                new_translations = json.load(f)
            
            # Carrega traduções existentes
            target_file = self.i18n_dir / f"{target_lang}.json"
            existing_translations = {}
            
            if target_file.exists():
                with open(target_file, 'r', encoding='utf-8') as f:
                    existing_translations = json.load(f)
            
            # Mescla traduções (novas sobrescrevem existentes)
            merged_translations = {**existing_translations, **new_translations}
            
            # Remove traduções pendentes se há versão traduzida
            for key, value in merged_translations.items():
                if isinstance(value, str) and value.startswith("TODO:"):
                    # Verifica se há versão traduzida
                    if key in new_translations and not new_translations[key].startswith("TODO:"):
                        merged_translations[key] = new_translations[key]
            
            # Salva arquivo mesclado
            with open(target_file, 'w', encoding='utf-8') as f:
                json.dump(merged_translations, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Traduções mescladas em: {target_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao mesclar traduções: {e}")
            return False
    
    def add_new_translation_key(self, key: str, translations: Dict[str, str]):
        """
        Adiciona nova chave de tradução em todos os idiomas.
        
        Args:
            key: Nova chave
            translations: Dicionário com traduções por idioma
        """
        logger.info(f"Adicionando nova chave: {key}")
        
        success = self.i18n.add_translation(key, translations)
        
        if success:
            logger.info(f"Chave '{key}' adicionada com sucesso")
        else:
            logger.error(f"Erro ao adicionar chave '{key}'")
        
        return success
    
    def cleanup_todo_translations(self, lang_code: str):
        """
        Remove traduções pendentes (TODO) de um idioma.
        
        Args:
            lang_code: Código do idioma
        """
        logger.info(f"Limpando traduções TODO de {lang_code}...")
        
        if lang_code not in self.i18n.translations:
            logger.error(f"Idioma não encontrado: {lang_code}")
            return False
        
        translations = self.i18n.translations[lang_code].copy()
        cleaned_count = 0
        
        for key, value in list(translations.items()):
            if isinstance(value, str) and value.startswith("TODO:"):
                del translations[key]
                cleaned_count += 1
        
        # Salva arquivo limpo
        target_file = self.i18n_dir / f"{lang_code}.json"
        with open(target_file, 'w', encoding='utf-8') as f:
            json.dump(translations, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Removidas {cleaned_count} traduções TODO de {lang_code}")
        return True


def main():
    """Função principal do script."""
    parser = argparse.ArgumentParser(
        description="Gerenciador de traduções para Omni Writer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python manage_translations.py --scan-missing
  python manage_translations.py --validate
  python manage_translations.py --export-report
  python manage_translations.py --create-missing-files
  python manage_translations.py --merge translations_en.json en_US
  python manage_translations.py --add-key "new_feature" --translations '{"pt_BR": "Nova funcionalidade", "en_US": "New feature"}'
        """
    )
    
    parser.add_argument(
        "--i18n-dir",
        default="shared/i18n",
        help="Diretório com arquivos de tradução (padrão: shared/i18n)"
    )
    
    parser.add_argument(
        "--scan-missing",
        action="store_true",
        help="Escaneia traduções faltantes"
    )
    
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Valida traduções existentes"
    )
    
    parser.add_argument(
        "--export-report",
        action="store_true",
        help="Exporta relatório completo de traduções"
    )
    
    parser.add_argument(
        "--create-missing-files",
        action="store_true",
        help="Cria arquivos com traduções faltantes"
    )
    
    parser.add_argument(
        "--merge",
        nargs=2,
        metavar=("SOURCE_FILE", "TARGET_LANG"),
        help="Mescla traduções de um arquivo para um idioma"
    )
    
    parser.add_argument(
        "--add-key",
        nargs=2,
        metavar=("KEY", "TRANSLATIONS"),
        help="Adiciona nova chave de tradução"
    )
    
    parser.add_argument(
        "--cleanup-todo",
        metavar="LANG_CODE",
        help="Remove traduções TODO de um idioma"
    )
    
    parser.add_argument(
        "--output-dir",
        default="missing_translations",
        help="Diretório de saída para arquivos de traduções faltantes"
    )
    
    parser.add_argument(
        "--output-file",
        default="translation_report.json",
        help="Arquivo de saída para relatório"
    )
    
    args = parser.parse_args()
    
    # Inicializa gerenciador
    manager = TranslationManager(args.i18n_dir)
    
    try:
        if args.scan_missing:
            missing = manager.scan_missing_translations()
            print("\n=== Traduções Faltantes ===")
            for lang, keys in missing.items():
                print(f"\n{lang}: {len(keys)} chaves faltantes")
                for key in keys[:5]:  # Mostra apenas as primeiras 5
                    print(f"  - {key}")
                if len(keys) > 5:
                    print(f"  ... e mais {len(keys) - 5} chaves")
        
        elif args.validate:
            issues = manager.validate_translations()
            print("\n=== Problemas de Validação ===")
            for lang, problems in issues.items():
                print(f"\n{lang}: {len(problems)} problemas")
                for problem in problems[:3]:  # Mostra apenas os primeiros 3
                    print(f"  - {problem}")
                if len(problems) > 3:
                    print(f"  ... e mais {len(problems) - 3} problemas")
        
        elif args.export_report:
            report = manager.export_translations_report(args.output_file)
            print(f"\n=== Relatório Exportado ===")
            print(f"Arquivo: {args.output_file}")
            print(f"Idiomas: {len(report['supported_languages'])}")
            print(f"Total de problemas: {sum(len(issues) for issues in report['validation_issues'].values())}")
        
        elif args.create_missing_files:
            manager.create_missing_translation_files(args.output_dir)
            print(f"\n=== Arquivos Criados ===")
            print(f"Diretório: {args.output_dir}")
        
        elif args.merge:
            source_file, target_lang = args.merge
            success = manager.merge_translations(source_file, target_lang)
            if success:
                print(f"\n=== Traduções Mescladas ===")
                print(f"Arquivo: {source_file}")
                print(f"Idioma: {target_lang}")
            else:
                print("Erro ao mesclar traduções")
        
        elif args.add_key:
            key, translations_json = args.add_key
            try:
                translations = json.loads(translations_json)
                success = manager.add_new_translation_key(key, translations)
                if success:
                    print(f"\n=== Chave Adicionada ===")
                    print(f"Chave: {key}")
                    print(f"Idiomas: {list(translations.keys())}")
                else:
                    print("Erro ao adicionar chave")
            except json.JSONDecodeError:
                print("Erro: formato JSON inválido para traduções")
        
        elif args.cleanup_todo:
            success = manager.cleanup_todo_translations(args.cleanup_todo)
            if success:
                print(f"\n=== Traduções TODO Removidas ===")
                print(f"Idioma: {args.cleanup_todo}")
            else:
                print("Erro ao limpar traduções TODO")
        
        else:
            # Executa todas as verificações
            print("=== Análise Completa de Traduções ===\n")
            
            # Escaneia traduções faltantes
            missing = manager.scan_missing_translations()
            print(f"Traduções faltantes: {sum(len(keys) for keys in missing.values())}")
            
            # Valida traduções
            issues = manager.validate_translations()
            print(f"Problemas encontrados: {sum(len(problems) for problems in issues.values())}")
            
            # Exporta relatório
            report = manager.export_translations_report(args.output_file)
            print(f"Relatório salvo em: {args.output_file}")
            
            # Mostra estatísticas
            print("\n=== Estatísticas por Idioma ===")
            for lang, stats in report['statistics'].items():
                print(f"{lang}: {stats['completion_percentage']}% completo "
                      f"({stats['complete_translations']}/{stats['total_keys']})")
    
    except Exception as e:
        logger.error(f"Erro durante execução: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 