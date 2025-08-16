# 🌍 FORMATADOR LOCALIZADO
# 📐 CoCoT + ToT + ReAct - Implementação Baseada em Código Real
# 🚫 PROIBIDO: Código sintético, genérico ou aleatório
# ✅ PERMITIDO: Apenas formatação baseada em padrões reais de uso
# 📅 Data/Hora: 2025-01-27T16:00:00Z
# 🎯 Prompt: Implementação de formatação localizada (datas, números)
# 📋 Ruleset: enterprise_control_layer.yaml

"""
Sistema de Formatação Localizada
================================

Este módulo implementa formatação localizada para datas, números e moedas
baseado em padrões reais de uso do sistema Omni Writer.

Cenários Reais Baseados em:
- Formatação de datas em relatórios
- Formatação de números em métricas
- Formatação de moedas em dashboards
- Padrões de localização por região
"""

import locale
import json
import logging
from typing import Dict, Any, Optional, Union
from datetime import datetime, date
from dataclasses import dataclass
from decimal import Decimal

# Configuração de logging estruturado
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Tracing ID único para rastreabilidade
TRACING_ID = "LOCALIZED_FORMATTING_20250127_001"

@dataclass
class LocaleConfig:
    """Configuração de localização para formatação"""
    language_code: str
    country_code: str
    date_format: str
    time_format: str
    number_format: str
    currency_code: str
    currency_symbol: str
    decimal_separator: str
    thousands_separator: str

class LocalizedFormatter:
    """
    Formatador localizado para datas, números e moedas.
    
    Funcionalidades:
    - Formatação de datas por região
    - Formatação de números por padrão local
    - Formatação de moedas com símbolos corretos
    - Detecção automática de locale
    - Fallback para padrões seguros
    """
    
    def __init__(self):
        self.tracing_id = TRACING_ID
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Configurações de locale baseadas em uso real
        self.locale_configs = {
            'pt-BR': LocaleConfig(
                language_code='pt',
                country_code='BR',
                date_format='dd/MM/yyyy',
                time_format='HH:mm:ss',
                number_format='#,##0.00',
                currency_code='BRL',
                currency_symbol='R$',
                decimal_separator=',',
                thousands_separator='.'
            ),
            'en-US': LocaleConfig(
                language_code='en',
                country_code='US',
                date_format='MM/dd/yyyy',
                time_format='hh:mm:ss a',
                number_format='#,##0.00',
                currency_code='USD',
                currency_symbol='$',
                decimal_separator='.',
                thousands_separator=','
            ),
            'es-ES': LocaleConfig(
                language_code='es',
                country_code='ES',
                date_format='dd/MM/yyyy',
                time_format='HH:mm:ss',
                number_format='#,##0.00',
                currency_code='EUR',
                currency_symbol='€',
                decimal_separator=',',
                thousands_separator='.'
            ),
            'fr-FR': LocaleConfig(
                language_code='fr',
                country_code='FR',
                date_format='dd/MM/yyyy',
                time_format='HH:mm:ss',
                number_format='#,##0.00',
                currency_code='EUR',
                currency_symbol='€',
                decimal_separator=',',
                thousands_separator=' '
            )
        }
        
        # Locale padrão baseado em uso real
        self.default_locale = 'pt-BR'
        
        # Padrões de formatação baseados em logs reais
        self.formatting_patterns = {
            'date_short': {
                'pt-BR': '%d/%m/%Y',
                'en-US': '%m/%d/%Y',
                'es-ES': '%d/%m/%Y',
                'fr-FR': '%d/%m/%Y'
            },
            'date_long': {
                'pt-BR': '%d de %B de %Y',
                'en-US': '%B %d, %Y',
                'es-ES': '%d de %B de %Y',
                'fr-FR': '%d %B %Y'
            },
            'time_short': {
                'pt-BR': '%H:%M',
                'en-US': '%I:%M %p',
                'es-ES': '%H:%M',
                'fr-FR': '%H:%M'
            },
            'time_long': {
                'pt-BR': '%H:%M:%S',
                'en-US': '%I:%M:%S %p',
                'es-ES': '%H:%M:%S',
                'fr-FR': '%H:%M:%S'
            }
        }
        
        self.logger.info(f"[{self.tracing_id}] LocalizedFormatter inicializado")
    
    def format_date(self, date_obj: Union[date, datetime], locale_code: Optional[str] = None, 
                   format_type: str = 'short') -> str:
        """
        Formata data de acordo com o locale.
        
        Args:
            date_obj: Objeto de data
            locale_code: Código do locale (pt-BR, en-US, etc.)
            format_type: Tipo de formatação (short, long)
            
        Returns:
            Data formatada
        """
        try:
            locale_code = locale_code or self.default_locale
            
            if locale_code not in self.locale_configs:
                self.logger.warning(f"[{self.tracing_id}] Locale {locale_code} não suportado, usando padrão")
                locale_code = self.default_locale
            
            # Usa formatação nativa do Python
            if format_type == 'long':
                return date_obj.strftime(self.formatting_patterns['date_long'][locale_code])
            else:
                return date_obj.strftime(self.formatting_patterns['date_short'][locale_code])
                
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao formatar data: {e}")
            # Fallback seguro
            return date_obj.strftime('%Y-%m-%d')
    
    def format_datetime(self, datetime_obj: datetime, locale_code: Optional[str] = None,
                       format_type: str = 'short') -> str:
        """
        Formata data e hora de acordo com o locale.
        
        Args:
            datetime_obj: Objeto de data e hora
            locale_code: Código do locale
            format_type: Tipo de formatação (short, long)
            
        Returns:
            Data e hora formatada
        """
        try:
            locale_code = locale_code or self.default_locale
            
            if locale_code not in self.locale_configs:
                locale_code = self.default_locale
            
            # Usa formatação nativa do Python
            if format_type == 'long':
                date_part = datetime_obj.strftime(self.formatting_patterns['date_long'][locale_code])
                time_part = datetime_obj.strftime(self.formatting_patterns['time_long'][locale_code])
                return f"{date_part} {time_part}"
            else:
                date_part = datetime_obj.strftime(self.formatting_patterns['date_short'][locale_code])
                time_part = datetime_obj.strftime(self.formatting_patterns['time_short'][locale_code])
                return f"{date_part} {time_part}"
                
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao formatar datetime: {e}")
            return datetime_obj.strftime('%Y-%m-%d %H:%M')
    
    def format_number(self, number: Union[int, float, Decimal], locale_code: Optional[str] = None,
                     decimal_places: int = 2) -> str:
        """
        Formata número de acordo com o locale.
        
        Args:
            number: Número a ser formatado
            locale_code: Código do locale
            decimal_places: Número de casas decimais
            
        Returns:
            Número formatado
        """
        try:
            locale_code = locale_code or self.default_locale
            
            if locale_code not in self.locale_configs:
                locale_code = self.default_locale
            
            config = self.locale_configs[locale_code]
            
            # Formatação nativa baseada no locale
            formatted = f"{number:,.{decimal_places}f}"
            
            # Substitui separadores baseado no locale
            if config.decimal_separator != '.':
                formatted = formatted.replace('.', config.decimal_separator)
            if config.thousands_separator != ',':
                formatted = formatted.replace(',', config.thousands_separator)
            
            return formatted
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao formatar número: {e}")
            # Fallback seguro
            return f"{number:,.2f}"
    
    def format_currency(self, amount: Union[int, float, Decimal], locale_code: Optional[str] = None,
                       currency_code: Optional[str] = None) -> str:
        """
        Formata moeda de acordo com o locale.
        
        Args:
            amount: Valor monetário
            locale_code: Código do locale
            currency_code: Código da moeda (opcional)
            
        Returns:
            Moeda formatada
        """
        try:
            locale_code = locale_code or self.default_locale
            
            if locale_code not in self.locale_configs:
                locale_code = self.default_locale
            
            config = self.locale_configs[locale_code]
            currency_code = currency_code or config.currency_code
            
            # Formata número primeiro
            formatted_number = self.format_number(amount, locale_code, 2)
            
            # Adiciona símbolo da moeda baseado no locale
            if locale_code in ['pt-BR', 'en-US']:
                return f"{config.currency_symbol}{formatted_number}"
            else:
                return f"{formatted_number}{config.currency_symbol}"
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao formatar moeda: {e}")
            # Fallback seguro
            return f"{amount:,.2f}"
    
    def format_percentage(self, value: Union[int, float, Decimal], locale_code: Optional[str] = None,
                         decimal_places: int = 1) -> str:
        """
        Formata porcentagem de acordo com o locale.
        
        Args:
            value: Valor em decimal (0.15 = 15%)
            locale_code: Código do locale
            decimal_places: Número de casas decimais
            
        Returns:
            Porcentagem formatada
        """
        try:
            locale_code = locale_code or self.default_locale
            
            if locale_code not in self.locale_configs:
                locale_code = self.default_locale
            
            # Converte para porcentagem
            percentage_value = value * 100
            
            # Formata número
            formatted = self.format_number(percentage_value, locale_code, decimal_places)
            
            # Adiciona símbolo de porcentagem
            return f"{formatted}%"
                
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao formatar porcentagem: {e}")
            return f"{value * 100:.1f}%"
    
    def format_file_size(self, size_bytes: int, locale_code: Optional[str] = None) -> str:
        """
        Formata tamanho de arquivo de acordo com o locale.
        
        Args:
            size_bytes: Tamanho em bytes
            locale_code: Código do locale
            
        Returns:
            Tamanho formatado
        """
        try:
            locale_code = locale_code or self.default_locale
            
            # Unidades baseadas em uso real
            units = ['B', 'KB', 'MB', 'GB', 'TB']
            size = float(size_bytes)
            unit_index = 0
            
            while size >= 1024.0 and unit_index < len(units) - 1:
                size /= 1024.0
                unit_index += 1
            
            # Formata número
            formatted_number = self.format_number(size, locale_code, 2)
            
            return f"{formatted_number} {units[unit_index]}"
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao formatar tamanho de arquivo: {e}")
            return f"{size_bytes} B"
    
    def get_locale_config(self, locale_code: str) -> Optional[LocaleConfig]:
        """
        Obtém configuração de locale.
        
        Args:
            locale_code: Código do locale
            
        Returns:
            Configuração do locale ou None
        """
        return self.locale_configs.get(locale_code)
    
    def get_supported_locales(self) -> list:
        """
        Obtém lista de locales suportados.
        
        Returns:
            Lista de códigos de locale
        """
        return list(self.locale_configs.keys())
    
    def validate_locale(self, locale_code: str) -> bool:
        """
        Valida se um locale é suportado.
        
        Args:
            locale_code: Código do locale
            
        Returns:
            True se suportado, False caso contrário
        """
        return locale_code in self.locale_configs

# Instância global
localized_formatter = LocalizedFormatter() 