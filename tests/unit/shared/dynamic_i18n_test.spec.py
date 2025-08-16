#!/usr/bin/env python3
"""
Testes unitários para o sistema de internacionalização dinâmica.
Cobertura: tradução, formatação, detecção de idioma e persistência.
"""

import pytest
import json
import os
import tempfile
from datetime import datetime
from unittest.mock import patch, mock_open
from shared.dynamic_i18n import DynamicI18n, LanguageInfo, TranslationEntry


class TestDynamicI18n:
    """Testes para a classe DynamicI18n."""
    
    @pytest.fixture
    def temp_i18n_dir(self):
        """Cria diretório temporário para testes de i18n."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Cria arquivos de tradução de teste
            translations = {
                "pt_BR": {
                    "app_title": "Omni Writer",
                    "login": "Entrar",
                    "welcome": "Bem-vindo {name}",
                    "articles_count": "Você tem {count} artigos"
                },
                "en_US": {
                    "app_title": "Omni Writer",
                    "login": "Login",
                    "welcome": "Welcome {name}",
                    "articles_count": "You have {count} articles"
                },
                "es_ES": {
                    "app_title": "Omni Writer",
                    "login": "Iniciar sesión",
                    "welcome": "Bienvenido {name}",
                    "articles_count": "Tienes {count} artículos"
                }
            }
            
            for lang_code, trans in translations.items():
                file_path = os.path.join(temp_dir, f"{lang_code}.json")
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(trans, f, ensure_ascii=False, indent=2)
            
            yield temp_dir
    
    @pytest.fixture
    def i18n_instance(self, temp_i18n_dir):
        """Instância de DynamicI18n para testes."""
        return DynamicI18n(i18n_dir=temp_i18n_dir)
    
    def test_initialization(self, temp_i18n_dir):
        """Testa inicialização do sistema de i18n."""
        i18n = DynamicI18n(i18n_dir=temp_i18n_dir)
        
        assert i18n.current_language == "pt_BR"
        assert i18n.fallback_language == "en_US"
        assert "pt_BR" in i18n.translations
        assert "en_US" in i18n.translations
        assert "es_ES" in i18n.translations
    
    def test_set_language_valid(self, i18n_instance):
        """Testa definição de idioma válido."""
        # Testa mudança para inglês
        result = i18n_instance.set_language("en_US")
        assert result is True
        assert i18n_instance.current_language == "en_US"
        
        # Testa mudança para espanhol
        result = i18n_instance.set_language("es_ES")
        assert result is True
        assert i18n_instance.current_language == "es_ES"
    
    def test_set_language_invalid(self, i18n_instance):
        """Testa definição de idioma inválido."""
        # Idioma não suportado
        result = i18n_instance.set_language("invalid_lang")
        assert result is False
        assert i18n_instance.current_language == "pt_BR"  # Mantém o atual
    
    def test_translate_basic(self, i18n_instance):
        """Testa tradução básica."""
        # Testa em português
        assert i18n_instance.translate("app_title") == "Omni Writer"
        assert i18n_instance.translate("login") == "Entrar"
        
        # Muda para inglês
        i18n_instance.set_language("en_US")
        assert i18n_instance.translate("login") == "Login"
        
        # Muda para espanhol
        i18n_instance.set_language("es_ES")
        assert i18n_instance.translate("login") == "Iniciar sesión"
    
    def test_translate_with_variables(self, i18n_instance):
        """Testa tradução com interpolação de variáveis."""
        # Testa em português
        result = i18n_instance.translate("welcome", name="João")
        assert result == "Bem-vindo João"
        
        result = i18n_instance.translate("articles_count", count=5)
        assert result == "Você tem 5 artigos"
        
        # Testa em inglês
        i18n_instance.set_language("en_US")
        result = i18n_instance.translate("welcome", name="John")
        assert result == "Welcome John"
        
        result = i18n_instance.translate("articles_count", count=3)
        assert result == "You have 3 articles"
        
        # Testa em espanhol
        i18n_instance.set_language("es_ES")
        result = i18n_instance.translate("welcome", name="Juan")
        assert result == "Bienvenido Juan"
        
        result = i18n_instance.translate("articles_count", count=7)
        assert result == "Tienes 7 artículos"
    
    def test_translate_fallback(self, i18n_instance):
        """Testa fallback de tradução."""
        # Chave que não existe em nenhum idioma
        result = i18n_instance.translate("nonexistent_key")
        assert result == "nonexistent_key"
        
        # Chave que existe apenas no fallback
        i18n_instance.translations["en_US"]["fallback_only"] = "Fallback text"
        result = i18n_instance.translate("fallback_only")
        assert result == "Fallback text"
    
    def test_format_date(self, i18n_instance):
        """Testa formatação de data."""
        test_date = datetime(2025, 1, 27, 14, 30, 0)
        
        # Testa formatação em português
        result = i18n_instance.format_date(test_date)
        assert result == "27/01/2025"
        
        # Testa formatação em inglês
        i18n_instance.set_language("en_US")
        result = i18n_instance.format_date(test_date)
        assert result == "01/27/2025"
    
    def test_format_time(self, i18n_instance):
        """Testa formatação de hora."""
        test_time = datetime(2025, 1, 27, 14, 30, 0)
        
        # Testa formatação em português
        result = i18n_instance.format_time(test_time)
        assert result == "14:30"
        
        # Testa formatação em inglês
        i18n_instance.set_language("en_US")
        result = i18n_instance.format_time(test_time)
        assert result == "14:30"
    
    def test_format_number(self, i18n_instance):
        """Testa formatação de números."""
        test_number = 1234567.89
        
        # Testa formatação em português (usa vírgula)
        result = i18n_instance.format_number(test_number)
        assert "1.234.567" in result or "1,234,567" in result
        
        # Testa formatação em inglês (usa ponto)
        i18n_instance.set_language("en_US")
        result = i18n_instance.format_number(test_number)
        assert "1,234,567" in result
    
    def test_format_currency(self, i18n_instance):
        """Testa formatação de moeda."""
        test_amount = 99.99
        
        # Testa formatação em português (BRL)
        result = i18n_instance.format_currency(test_amount)
        assert "R$" in result or "99,99" in result
        
        # Testa formatação em inglês (USD)
        i18n_instance.set_language("en_US")
        result = i18n_instance.format_currency(test_amount)
        assert "$" in result and "99.99" in result
        
        # Testa formatação em espanhol (EUR)
        i18n_instance.set_language("es_ES")
        result = i18n_instance.format_currency(test_amount)
        assert "€" in result
    
    def test_detect_language(self, i18n_instance):
        """Testa detecção de idioma."""
        # Texto em português
        result = i18n_instance.detect_language("Olá, como você está?")
        assert result == "pt_BR"
        
        # Texto em inglês
        result = i18n_instance.detect_language("Hello, how are you?")
        assert result == "en_US"
        
        # Texto em espanhol
        result = i18n_instance.detect_language("Hola, ¿cómo estás?")
        assert result == "es_ES"
        
        # Texto neutro (fallback para inglês)
        result = i18n_instance.detect_language("1234567890")
        assert result == "en_US"
    
    def test_get_language_info(self, i18n_instance):
        """Testa obtenção de informações de idioma."""
        # Informações do idioma atual
        info = i18n_instance.get_language_info()
        assert info is not None
        assert info.code == "pt_BR"
        assert info.name == "Portuguese (Brazil)"
        assert info.flag == "🇧🇷"
        
        # Informações de idioma específico
        info = i18n_instance.get_language_info("en_US")
        assert info is not None
        assert info.code == "en_US"
        assert info.name == "English (US)"
        assert info.flag == "🇺🇸"
        
        # Idioma inexistente
        info = i18n_instance.get_language_info("invalid")
        assert info is None
    
    def test_get_supported_languages(self, i18n_instance):
        """Testa obtenção de idiomas suportados."""
        languages = i18n_instance.get_supported_languages()
        
        assert "pt_BR" in languages
        assert "en_US" in languages
        assert "es_ES" in languages
        assert "fr_FR" in languages
        
        # Verifica estrutura das informações
        pt_info = languages["pt_BR"]
        assert isinstance(pt_info, LanguageInfo)
        assert pt_info.code == "pt_BR"
        assert pt_info.name == "Portuguese (Brazil)"
    
    def test_add_translation(self, i18n_instance, temp_i18n_dir):
        """Testa adição de novas traduções."""
        new_translations = {
            "pt_BR": "Nova funcionalidade",
            "en_US": "New feature",
            "es_ES": "Nueva funcionalidad"
        }
        
        result = i18n_instance.add_translation("new_feature", new_translations)
        assert result is True
        
        # Verifica se as traduções foram adicionadas
        assert i18n_instance.translate("new_feature") == "Nova funcionalidade"
        
        i18n_instance.set_language("en_US")
        assert i18n_instance.translate("new_feature") == "New feature"
        
        i18n_instance.set_language("es_ES")
        assert i18n_instance.translate("new_feature") == "Nueva funcionalidad"
    
    def test_get_missing_translations(self, i18n_instance):
        """Testa obtenção de traduções faltantes."""
        # Adiciona tradução apenas em português
        i18n_instance.translations["pt_BR"]["missing_key"] = "Chave faltante"
        
        # Verifica traduções faltantes em inglês
        missing = i18n_instance.get_missing_translations("en_US")
        assert "missing_key" in missing
        
        # Verifica traduções faltantes em espanhol
        missing = i18n_instance.get_missing_translations("es_ES")
        assert "missing_key" in missing
    
    def test_export_translations(self, i18n_instance):
        """Testa exportação de traduções."""
        # Exporta em formato JSON
        json_export = i18n_instance.export_translations("pt_BR", "json")
        assert isinstance(json_export, str)
        
        # Verifica se é JSON válido
        exported_data = json.loads(json_export)
        assert "app_title" in exported_data
        assert "login" in exported_data
        
        # Exporta em formato CSV
        csv_export = i18n_instance.export_translations("pt_BR", "csv")
        assert isinstance(csv_export, str)
        assert "key,value" in csv_export
        assert "app_title" in csv_export
    
    def test_import_translations(self, i18n_instance):
        """Testa importação de traduções."""
        # Dados para importar
        import_data = json.dumps({
            "imported_key": "Chave importada",
            "another_key": "Outra chave"
        })
        
        result = i18n_instance.import_translations("pt_BR", import_data, "json")
        assert result is True
        
        # Verifica se as traduções foram importadas
        assert i18n_instance.translate("imported_key") == "Chave importada"
        assert i18n_instance.translate("another_key") == "Outra chave"
    
    def test_persistence(self, temp_i18n_dir):
        """Testa persistência de preferência de idioma."""
        # Simula arquivo de preferência existente
        preference_data = {
            "language": "en_US",
            "updated_at": "2025-01-27T14:30:00"
        }
        
        preference_file = os.path.join(temp_i18n_dir, "user_preference.json")
        with open(preference_file, 'w', encoding='utf-8') as f:
            json.dump(preference_data, f)
        
        # Cria nova instância (deve carregar a preferência)
        i18n = DynamicI18n(i18n_dir=temp_i18n_dir)
        assert i18n.current_language == "en_US"
    
    def test_error_handling(self, temp_i18n_dir):
        """Testa tratamento de erros."""
        # Testa com diretório inexistente
        i18n = DynamicI18n(i18n_dir="/nonexistent/directory")
        assert i18n.current_language == "pt_BR"  # Fallback
        
        # Testa tradução com arquivo corrompido
        corrupted_file = os.path.join(temp_i18n_dir, "corrupted.json")
        with open(corrupted_file, 'w') as f:
            f.write("invalid json content")
        
        # Não deve quebrar
        i18n = DynamicI18n(i18n_dir=temp_i18n_dir)
        assert i18n.current_language == "pt_BR"


class TestLanguageInfo:
    """Testes para a classe LanguageInfo."""
    
    def test_language_info_creation(self):
        """Testa criação de LanguageInfo."""
        info = LanguageInfo(
            code="pt_BR",
            name="Portuguese (Brazil)",
            native_name="Português (Brasil)",
            flag="🇧🇷"
        )
        
        assert info.code == "pt_BR"
        assert info.name == "Portuguese (Brazil)"
        assert info.native_name == "Português (Brasil)"
        assert info.flag == "🇧🇷"
        assert info.direction == "ltr"  # Valor padrão
        assert info.currency == "USD"   # Valor padrão
    
    def test_language_info_with_custom_values(self):
        """Testa LanguageInfo com valores customizados."""
        info = LanguageInfo(
            code="ar_SA",
            name="Arabic (Saudi Arabia)",
            native_name="العربية (السعودية)",
            flag="🇸🇦",
            direction="rtl",
            currency="SAR"
        )
        
        assert info.direction == "rtl"
        assert info.currency == "SAR"


class TestTranslationEntry:
    """Testes para a classe TranslationEntry."""
    
    def test_translation_entry_creation(self):
        """Testa criação de TranslationEntry."""
        entry = TranslationEntry(
            key="welcome",
            value="Bem-vindo {name}",
            context="Greeting message",
            variables=["name"]
        )
        
        assert entry.key == "welcome"
        assert entry.value == "Bem-vindo {name}"
        assert entry.context == "Greeting message"
        assert entry.variables == ["name"]
        assert entry.plural_forms is None  # Valor padrão


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 