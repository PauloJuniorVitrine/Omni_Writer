#!/usr/bin/env python3
"""
Sistema de Internacionalização Dinâmica para Omni Writer.
Suporte a múltiplos idiomas com troca em tempo real e persistência.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from dataclasses import dataclass, asdict
from pathlib import Path

# Configuração de logging
i18n_logger = logging.getLogger('dynamic_i18n')
i18n_logger.setLevel(logging.INFO)

@dataclass
class LanguageInfo:
    """Informações de um idioma."""
    code: str
    name: str
    native_name: str
    flag: str
    direction: str = "ltr"
    date_format: str = "%Y-%m-%d"
    time_format: str = "%H:%M:%S"
    currency: str = "USD"
    locale: str = "en_US"

@dataclass
class TranslationEntry:
    """Entrada de tradução."""
    key: str
    value: str
    context: Optional[str] = None
    plural_forms: Optional[Dict[str, str]] = None
    variables: Optional[List[str]] = None

class DynamicI18n:
    """
    Sistema de internacionalização dinâmica.
    
    Funcionalidades:
    - Suporte a múltiplos idiomas
    - Troca de idioma em tempo real
    - Persistência de preferência
    - Fallback automático
    - Interpolação de variáveis
    - Formatação de datas e números
    - Detecção automática de idioma
    """
    
    def __init__(self, i18n_dir: str = "shared/i18n"):
        self.i18n_dir = i18n_dir
        self.current_language = "pt_BR"
        self.fallback_language = "en_US"
        self.translations = {}
        self.languages = {}
        
        # Configuração de idiomas suportados
        self.supported_languages = {
            "pt_BR": LanguageInfo(
                code="pt_BR",
                name="Portuguese (Brazil)",
                native_name="Português (Brasil)",
                flag="🇧🇷",
                date_format="%d/%m/%Y",
                time_format="%H:%M",
                currency="BRL",
                locale="pt_BR"
            ),
            "en_US": LanguageInfo(
                code="en_US",
                name="English (US)",
                native_name="English (US)",
                flag="🇺🇸",
                date_format="%Y-%m-%d",
                time_format="%H:%M",
                currency="USD",
                locale="en_US"
            ),
            "es_ES": LanguageInfo(
                code="es_ES",
                name="Spanish (Spain)",
                native_name="Español (España)",
                flag="🇪🇸",
                date_format="%d/%m/%Y",
                time_format="%H:%M",
                currency="EUR",
                locale="es_ES"
            ),
            "fr_FR": LanguageInfo(
                code="fr_FR",
                name="French (France)",
                native_name="Français (France)",
                flag="🇫🇷",
                date_format="%d/%m/%Y",
                time_format="%H:%M",
                currency="EUR",
                locale="fr_FR"
            )
        }
        
        self._load_translations()
        self._load_user_preference()
    
    def _load_translations(self):
        """Carrega todas as traduções disponíveis."""
        try:
            for lang_code in self.supported_languages:
                file_path = os.path.join(self.i18n_dir, f"{lang_code}.json")
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        self.translations[lang_code] = json.load(f)
                    i18n_logger.info(f"Traduções carregadas para {lang_code}")
                else:
                    i18n_logger.warning(f"Arquivo de tradução não encontrado: {file_path}")
            
            # Carrega idiomas dinamicamente
            self.languages = self.supported_languages
            
        except Exception as e:
            i18n_logger.error(f"Erro ao carregar traduções: {e}")
    
    def _load_user_preference(self):
        """Carrega preferência de idioma do usuário."""
        try:
            # Tenta carregar de localStorage (simulado)
            preference_file = os.path.join(self.i18n_dir, "user_preference.json")
            if os.path.exists(preference_file):
                with open(preference_file, 'r', encoding='utf-8') as f:
                    preference = json.load(f)
                    if preference.get('language') in self.supported_languages:
                        self.current_language = preference['language']
                        i18n_logger.info(f"Preferência carregada: {self.current_language}")
            
            # Fallback para detecção automática
            if self.current_language not in self.translations:
                self.current_language = self.fallback_language
                
        except Exception as e:
            i18n_logger.error(f"Erro ao carregar preferência: {e}")
    
    def _save_user_preference(self):
        """Salva preferência de idioma do usuário."""
        try:
            preference = {
                'language': self.current_language,
                'updated_at': datetime.now().isoformat()
            }
            
            preference_file = os.path.join(self.i18n_dir, "user_preference.json")
            with open(preference_file, 'w', encoding='utf-8') as f:
                json.dump(preference, f, indent=2, ensure_ascii=False)
            
            i18n_logger.info(f"Preferência salva: {self.current_language}")
            
        except Exception as e:
            i18n_logger.error(f"Erro ao salvar preferência: {e}")
    
    def set_language(self, language_code: str) -> bool:
        """
        Define o idioma atual.
        
        Args:
            language_code: Código do idioma
        
        Returns:
            True se o idioma foi definido com sucesso
        """
        if language_code not in self.supported_languages:
            i18n_logger.warning(f"Idioma não suportado: {language_code}")
            return False
        
        if language_code not in self.translations:
            i18n_logger.warning(f"Traduções não disponíveis para: {language_code}")
            return False
        
        self.current_language = language_code
        self._save_user_preference()
        
        i18n_logger.info(f"Idioma alterado para: {language_code}")
        return True
    
    def get_language(self) -> str:
        """
        Obtém o idioma atual.
        
        Returns:
            Código do idioma atual
        """
        return self.current_language
    
    def get_language_info(self, language_code: str = None) -> Optional[LanguageInfo]:
        """
        Obtém informações de um idioma.
        
        Args:
            language_code: Código do idioma (opcional)
        
        Returns:
            Informações do idioma ou None
        """
        if language_code is None:
            language_code = self.current_language
        
        return self.languages.get(language_code)
    
    def get_supported_languages(self) -> Dict[str, LanguageInfo]:
        """
        Obtém lista de idiomas suportados.
        
        Returns:
            Dicionário de idiomas suportados
        """
        return self.languages.copy()
    
    def translate(self, key: str, language_code: str = None, **variables) -> str:
        """
        Traduz uma chave para o idioma especificado.
        
        Args:
            key: Chave de tradução
            language_code: Código do idioma (opcional)
            **variables: Variáveis para interpolação
        
        Returns:
            Texto traduzido
        """
        if language_code is None:
            language_code = self.current_language
        
        # Busca tradução
        translation = self._get_translation(key, language_code)
        
        if not translation:
            # Fallback para idioma padrão
            translation = self._get_translation(key, self.fallback_language)
        
        if not translation:
            # Fallback para a própria chave
            translation = key
        
        # Aplica interpolação de variáveis
        if variables:
            translation = self._interpolate_variables(translation, variables)
        
        return translation
    
    def _get_translation(self, key: str, language_code: str) -> Optional[str]:
        """
        Obtém tradução específica.
        
        Args:
            key: Chave de tradução
            language_code: Código do idioma
        
        Returns:
            Tradução ou None
        """
        try:
            # Suporte a chaves aninhadas (ex: "user.profile.name")
            keys = key.split('.')
            translation = self.translations.get(language_code, {})
            
            for k in keys:
                if isinstance(translation, dict):
                    translation = translation.get(k)
                else:
                    return None
            
            return str(translation) if translation is not None else None
            
        except Exception as e:
            i18n_logger.error(f"Erro ao buscar tradução {key} em {language_code}: {e}")
            return None
    
    def _interpolate_variables(self, text: str, variables: Dict[str, Any]) -> str:
        """
        Aplica interpolação de variáveis no texto.
        
        Args:
            text: Texto com placeholders
            variables: Variáveis para substituição
        
        Returns:
            Texto com variáveis interpoladas
        """
        try:
            for key, value in variables.items():
                placeholder = f"{{{key}}}"
                text = text.replace(placeholder, str(value))
            
            return text
            
        except Exception as e:
            i18n_logger.error(f"Erro na interpolação: {e}")
            return text
    
    def format_date(self, date: datetime, language_code: str = None) -> str:
        """
        Formata data no idioma especificado.
        
        Args:
            date: Data para formatar
            language_code: Código do idioma (opcional)
        
        Returns:
            Data formatada
        """
        if language_code is None:
            language_code = self.current_language
        
        lang_info = self.get_language_info(language_code)
        if lang_info:
            return date.strftime(lang_info.date_format)
        
        return date.strftime("%Y-%m-%d")
    
    def format_time(self, time: datetime, language_code: str = None) -> str:
        """
        Formata hora no idioma especificado.
        
        Args:
            time: Hora para formatar
            language_code: Código do idioma (opcional)
        
        Returns:
            Hora formatada
        """
        if language_code is None:
            language_code = self.current_language
        
        lang_info = self.get_language_info(language_code)
        if lang_info:
            return time.strftime(lang_info.time_format)
        
        return time.strftime("%H:%M")
    
    def format_number(self, number: Union[int, float], language_code: str = None) -> str:
        """
        Formata número no idioma especificado.
        
        Args:
            number: Número para formatar
            language_code: Código do idioma (opcional)
        
        Returns:
            Número formatado
        """
        if language_code is None:
            language_code = self.current_language
        
        # Implementação básica - pode ser expandida com locale
        if language_code in ["pt_BR", "es_ES", "fr_FR"]:
            # Usa vírgula como separador decimal
            return str(number).replace('.', ',')
        else:
            # Usa ponto como separador decimal
            return str(number)
    
    def format_currency(self, amount: float, language_code: str = None) -> str:
        """
        Formata moeda no idioma especificado.
        
        Args:
            amount: Valor para formatar
            language_code: Código do idioma (opcional)
        
        Returns:
            Moeda formatada
        """
        if language_code is None:
            language_code = self.current_language
        
        lang_info = self.get_language_info(language_code)
        if not lang_info:
            return f"${amount:.2f}"
        
        currency_symbols = {
            "USD": "$",
            "BRL": "R$",
            "EUR": "€"
        }
        
        symbol = currency_symbols.get(lang_info.currency, "$")
        formatted_number = self.format_number(amount, language_code)
        
        if language_code in ["pt_BR", "es_ES", "fr_FR"]:
            return f"{symbol} {formatted_number}"
        else:
            return f"{symbol}{formatted_number}"
    
    def detect_language(self, text: str) -> Optional[str]:
        """
        Detecta idioma de um texto.
        
        Args:
            text: Texto para análise
        
        Returns:
            Código do idioma detectado ou None
        """
        # Implementação básica - pode ser expandida com bibliotecas como langdetect
        text_lower = text.lower()
        
        # Palavras características de cada idioma
        portuguese_words = ['de', 'da', 'do', 'para', 'com', 'não', 'que', 'seu', 'sua']
        spanish_words = ['de', 'la', 'el', 'para', 'con', 'no', 'que', 'su', 'por']
        french_words = ['de', 'la', 'le', 'pour', 'avec', 'non', 'que', 'son', 'sa']
        
        pt_score = sum(1 for word in portuguese_words if word in text_lower)
        es_score = sum(1 for word in spanish_words if word in text_lower)
        fr_score = sum(1 for word in french_words if word in text_lower)
        
        if pt_score > es_score and pt_score > fr_score:
            return "pt_BR"
        elif es_score > pt_score and es_score > fr_score:
            return "es_ES"
        elif fr_score > pt_score and fr_score > es_score:
            return "fr_FR"
        else:
            return "en_US"
    
    def add_translation(self, key: str, translations: Dict[str, str]) -> bool:
        """
        Adiciona nova tradução.
        
        Args:
            key: Chave de tradução
            translations: Dicionário com traduções por idioma
        
        Returns:
            True se adicionado com sucesso
        """
        try:
            for lang_code, translation in translations.items():
                if lang_code in self.translations:
                    self.translations[lang_code][key] = translation
            
            # Salva no arquivo
            self._save_translations()
            
            i18n_logger.info(f"Tradução adicionada: {key}")
            return True
            
        except Exception as e:
            i18n_logger.error(f"Erro ao adicionar tradução: {e}")
            return False
    
    def _save_translations(self):
        """Salva traduções nos arquivos JSON."""
        try:
            for lang_code, translations in self.translations.items():
                file_path = os.path.join(self.i18n_dir, f"{lang_code}.json")
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(translations, f, indent=2, ensure_ascii=False)
            
            i18n_logger.info("Traduções salvas")
            
        except Exception as e:
            i18n_logger.error(f"Erro ao salvar traduções: {e}")
    
    def get_missing_translations(self, language_code: str) -> List[str]:
        """
        Obtém chaves sem tradução em um idioma.
        
        Args:
            language_code: Código do idioma
        
        Returns:
            Lista de chaves sem tradução
        """
        if language_code not in self.translations:
            return []
        
        # Obtém todas as chaves do idioma de referência
        reference_lang = self.fallback_language
        if reference_lang not in self.translations:
            return []
        
        reference_keys = set(self.translations[reference_lang].keys())
        current_keys = set(self.translations[language_code].keys())
        
        return list(reference_keys - current_keys)
    
    def export_translations(self, language_code: str, format: str = "json") -> str:
        """
        Exporta traduções de um idioma.
        
        Args:
            language_code: Código do idioma
            format: Formato de exportação (json, csv, po)
        
        Returns:
            Traduções exportadas
        """
        if language_code not in self.translations:
            return ""
        
        translations = self.translations[language_code]
        
        if format == "json":
            return json.dumps(translations, indent=2, ensure_ascii=False)
        elif format == "csv":
            # Implementar exportação CSV
            lines = ["key,value"]
            for key, value in translations.items():
                lines.append(f'"{key}","{value}"')
            return "\n".join(lines)
        else:
            return json.dumps(translations, indent=2, ensure_ascii=False)
    
    def import_translations(self, language_code: str, data: str, format: str = "json") -> bool:
        """
        Importa traduções para um idioma.
        
        Args:
            language_code: Código do idioma
            data: Dados para importar
            format: Formato dos dados (json, csv, po)
        
        Returns:
            True se importado com sucesso
        """
        try:
            if format == "json":
                translations = json.loads(data)
            elif format == "csv":
                # Implementar importação CSV
                translations = {}
                lines = data.strip().split('\n')[1:]  # Pula header
                for line in lines:
                    if ',' in line:
                        key, value = line.split(',', 1)
                        translations[key.strip('"')] = value.strip('"')
            else:
                return False
            
            if language_code not in self.translations:
                self.translations[language_code] = {}
            
            self.translations[language_code].update(translations)
            self._save_translations()
            
            i18n_logger.info(f"Traduções importadas para {language_code}")
            return True
            
        except Exception as e:
            i18n_logger.error(f"Erro ao importar traduções: {e}")
            return False

# Instância global
dynamic_i18n = DynamicI18n() 