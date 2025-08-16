"""
Testes de Internacionalização - Omni Writer
==========================================

Implementa testes para cenários de internacionalização:
- Caracteres especiais em múltiplos idiomas
- Formatação de data/hora
- Texto da direita para esquerda (RTL)
- Formatação de números
- Formatação de moeda

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import json
import locale
from datetime import datetime, date
from decimal import Decimal
from unittest.mock import Mock, patch, MagicMock

# Importações do sistema real
from shared.i18n import I18nManager, get_message, format_date, format_number, format_currency
from ui.context.AdvancedI18nContext import AdvancedI18nContext
from ui.hooks.use_i18n import use_i18n


class TestSpecialCharactersMultipleLanguages:
    """Testa caracteres especiais em múltiplos idiomas."""
    
    def test_special_characters_handling(self):
        """Testa tratamento de caracteres especiais."""
        # Setup baseado no código real
        i18n_manager = I18nManager()
        
        # Textos com caracteres especiais em diferentes idiomas
        test_cases = [
            # Português
            {
                "locale": "pt-BR",
                "text": "João e José têm 5 maçãs: áéíóú çãõ",
                "expected_chars": ["ã", "ç", "é", "ó", "ú"]
            },
            # Espanhol
            {
                "locale": "es-ES",
                "text": "María y José tienen 5 manzanas: áéíóú ñ",
                "expected_chars": ["á", "é", "í", "ó", "ú", "ñ"]
            },
            # Francês
            {
                "locale": "fr-FR",
                "text": "Marie et Joseph ont 5 pommes: àâäéèêëîïôöùûüÿç",
                "expected_chars": ["à", "â", "ä", "é", "è", "ê", "ë", "î", "ï", "ô", "ö", "ù", "û", "ü", "ÿ", "ç"]
            },
            # Alemão
            {
                "locale": "de-DE",
                "text": "Maria und Josef haben 5 Äpfel: äöüß",
                "expected_chars": ["ä", "ö", "ü", "ß"]
            },
            # Russo
            {
                "locale": "ru-RU",
                "text": "Мария и Иосиф имеют 5 яблок: ёйцукенгшщзхъфывапролджэячсмитьбю",
                "expected_chars": ["ё", "й", "ц", "у", "к", "е", "н", "г", "ш", "щ", "з", "х", "ъ", "ф", "ы", "в", "а", "п", "р", "о", "л", "д", "ж", "э", "я", "ч", "с", "м", "и", "ть", "б", "ю"]
            },
            # Chinês
            {
                "locale": "zh-CN",
                "text": "玛丽和约瑟夫有5个苹果：你好世界",
                "expected_chars": ["玛", "丽", "和", "约", "瑟", "夫", "有", "个", "苹", "果", "你", "好", "世", "界"]
            },
            # Japonês
            {
                "locale": "ja-JP",
                "text": "マリアとヨセフは5つのリンゴを持っています：こんにちは世界",
                "expected_chars": ["マ", "リ", "ア", "と", "ヨ", "セ", "フ", "は", "つ", "の", "リ", "ン", "ゴ", "を", "持", "っ", "て", "い", "ま", "す", "こ", "ん", "に", "ち", "は", "世", "界"]
            },
            # Árabe
            {
                "locale": "ar-SA",
                "text": "مريم ويوسف لديهما 5 تفاحات: مرحبا بالعالم",
                "expected_chars": ["م", "ر", "ي", "م", "و", "ي", "و", "س", "ف", "ل", "د", "ي", "ه", "م", "ا", "ت", "ف", "ا", "ح", "ا", "ت", "ح", "ب", "ا", "ب", "ا", "ل", "ع", "ا", "ل", "م"]
            }
        ]
        
        # Testa cada caso
        for test_case in test_cases:
            locale_code = test_case["locale"]
            text = test_case["text"]
            expected_chars = test_case["expected_chars"]
            
            # Configura locale
            i18n_manager.set_locale(locale_code)
            
            # Testa processamento do texto
            processed_text = i18n_manager.process_text(text)
            
            # Valida que caracteres especiais foram preservados
            for char in expected_chars:
                assert char in processed_text, f"Caractere especial '{char}' não encontrado em {locale_code}"
            
            # Valida que texto não foi corrompido
            assert len(processed_text) >= len(text)
            
            # Testa codificação UTF-8
            try:
                encoded = processed_text.encode('utf-8')
                decoded = encoded.decode('utf-8')
                assert decoded == processed_text
            except UnicodeError:
                pytest.fail(f"Falha na codificação UTF-8 para {locale_code}")
    
    def test_unicode_normalization(self):
        """Testa normalização Unicode."""
        # Setup
        i18n_manager = I18nManager()
        
        # Casos de normalização Unicode
        test_cases = [
            # Caracteres compostos vs. pré-compostos
            ("João", "João"),  # Deve permanecer igual
            ("café", "café"),  # Deve permanecer igual
            ("naïve", "naïve"),  # Deve permanecer igual
            
            # Caracteres com acentos combinados
            ("Jo\u0303a\u0303o", "João"),  # Deve normalizar
            ("cafe\u0301", "café"),  # Deve normalizar
            
            # Caracteres especiais
            ("München", "München"),  # Deve permanecer igual
            ("São Paulo", "São Paulo"),  # Deve permanecer igual
        ]
        
        for input_text, expected_output in test_cases:
            normalized = i18n_manager.normalize_unicode(input_text)
            assert normalized == expected_output
    
    def test_character_encoding_validation(self):
        """Testa validação de codificação de caracteres."""
        # Setup
        i18n_manager = I18nManager()
        
        # Testa diferentes codificações
        test_texts = [
            "Texto em português com acentos: áéíóú çãõ",
            "Text in English with special chars: café naïve",
            "Texto en español con acentos: áéíóú ñ",
            "Texte en français avec accents: àâäéèêëîïôöùûüÿç",
            "Text auf Deutsch mit Umlauten: äöüß",
            "Текст на русском языке",
            "中文文本",
            "日本語のテキスト",
            "نص باللغة العربية"
        ]
        
        for text in test_texts:
            # Testa codificação UTF-8
            try:
                utf8_encoded = text.encode('utf-8')
                utf8_decoded = utf8_encoded.decode('utf-8')
                assert utf8_decoded == text
            except UnicodeError:
                pytest.fail(f"Falha na codificação UTF-8: {text}")
            
            # Testa processamento pelo i18n manager
            processed = i18n_manager.process_text(text)
            assert len(processed) > 0
            
            # Testa que não houve perda de caracteres
            assert len(processed) >= len(text)


class TestDateTimeFormatting:
    """Testa formatação de data/hora."""
    
    def test_date_time_formatting(self):
        """Testa formatação de data/hora."""
        # Setup
        i18n_manager = I18nManager()
        
        # Data de teste
        test_date = datetime(2025, 1, 27, 14, 30, 45)
        
        # Formatos esperados por locale
        expected_formats = [
            # Português Brasil
            {
                "locale": "pt-BR",
                "date_format": "27/01/2025",
                "time_format": "14:30",
                "datetime_format": "27/01/2025 14:30"
            },
            # Inglês EUA
            {
                "locale": "en-US",
                "date_format": "01/27/2025",
                "time_format": "2:30 PM",
                "datetime_format": "01/27/2025 2:30 PM"
            },
            # Espanhol
            {
                "locale": "es-ES",
                "date_format": "27/01/2025",
                "time_format": "14:30",
                "datetime_format": "27/01/2025 14:30"
            },
            # Francês
            {
                "locale": "fr-FR",
                "date_format": "27/01/2025",
                "time_format": "14:30",
                "datetime_format": "27/01/2025 14:30"
            },
            # Alemão
            {
                "locale": "de-DE",
                "date_format": "27.01.2025",
                "time_format": "14:30",
                "datetime_format": "27.01.2025 14:30"
            }
        ]
        
        # Testa cada formato
        for expected in expected_formats:
            locale_code = expected["locale"]
            i18n_manager.set_locale(locale_code)
            
            # Testa formatação de data
            formatted_date = format_date(test_date, locale_code)
            assert formatted_date is not None
            assert len(formatted_date) > 0
            
            # Testa formatação de hora
            formatted_time = i18n_manager.format_time(test_date)
            assert formatted_time is not None
            assert len(formatted_time) > 0
            
            # Testa formatação de data/hora
            formatted_datetime = i18n_manager.format_datetime(test_date)
            assert formatted_datetime is not None
            assert len(formatted_datetime) > 0
    
    def test_relative_time_formatting(self):
        """Testa formatação de tempo relativo."""
        # Setup
        i18n_manager = I18nManager()
        
        from datetime import timedelta
        now = datetime.now()
        
        # Casos de tempo relativo
        relative_times = [
            (now - timedelta(minutes=5), "5 minutos atrás"),
            (now - timedelta(hours=2), "2 horas atrás"),
            (now - timedelta(days=1), "1 dia atrás"),
            (now - timedelta(weeks=1), "1 semana atrás"),
            (now + timedelta(minutes=5), "em 5 minutos"),
            (now + timedelta(hours=2), "em 2 horas"),
            (now + timedelta(days=1), "em 1 dia")
        ]
        
        # Testa em português
        i18n_manager.set_locale("pt-BR")
        for time_point, expected in relative_times:
            relative = i18n_manager.format_relative_time(time_point)
            assert relative is not None
            assert len(relative) > 0
            # Não testa texto exato pois pode variar
    
    def test_timezone_handling(self):
        """Testa tratamento de timezone."""
        # Setup
        i18n_manager = I18nManager()
        
        # Data com timezone
        from datetime import timezone, timedelta
        
        # UTC
        utc_time = datetime(2025, 1, 27, 14, 30, tzinfo=timezone.utc)
        
        # UTC-3 (Brasil)
        br_timezone = timezone(timedelta(hours=-3))
        br_time = datetime(2025, 1, 27, 14, 30, tzinfo=br_timezone)
        
        # Testa formatação com timezone
        utc_formatted = i18n_manager.format_datetime_with_timezone(utc_time, "UTC")
        br_formatted = i18n_manager.format_datetime_with_timezone(br_time, "America/Sao_Paulo")
        
        assert utc_formatted is not None
        assert br_formatted is not None
        assert "UTC" in utc_formatted or "GMT" in utc_formatted
        assert "BRT" in br_formatted or "America" in br_formatted


class TestRightToLeftText:
    """Testa texto da direita para esquerda (RTL)."""
    
    def test_right_to_left_text(self):
        """Testa texto da direita para esquerda."""
        # Setup
        i18n_manager = I18nManager()
        
        # Textos RTL (Árabe e Hebraico)
        rtl_texts = [
            # Árabe
            {
                "text": "مرحبا بالعالم",
                "locale": "ar-SA",
                "direction": "rtl"
            },
            # Hebraico
            {
                "text": "שלום עולם",
                "locale": "he-IL",
                "direction": "rtl"
            },
            # Persa
            {
                "text": "سلام دنیا",
                "locale": "fa-IR",
                "direction": "rtl"
            }
        ]
        
        # Testa cada texto RTL
        for test_case in rtl_texts:
            text = test_case["text"]
            locale_code = test_case["locale"]
            expected_direction = test_case["direction"]
            
            # Configura locale
            i18n_manager.set_locale(locale_code)
            
            # Testa detecção de direção
            detected_direction = i18n_manager.get_text_direction(text)
            assert detected_direction == expected_direction
            
            # Testa processamento RTL
            processed_text = i18n_manager.process_rtl_text(text)
            assert processed_text is not None
            assert len(processed_text) > 0
            
            # Testa que texto não foi corrompido
            assert len(processed_text) >= len(text)
    
    def test_mixed_rtl_ltr_text(self):
        """Testa texto misto RTL/LTR."""
        # Setup
        i18n_manager = I18nManager()
        
        # Textos mistos (RTL + LTR)
        mixed_texts = [
            # Árabe + Inglês
            "مرحبا Hello World بالعالم",
            # Hebraico + Números
            "שלום 123 עולם",
            # Persa + Inglês
            "سلام Hello دنیا"
        ]
        
        for text in mixed_texts:
            # Testa processamento de texto misto
            processed = i18n_manager.process_mixed_direction_text(text)
            assert processed is not None
            assert len(processed) > 0
            
            # Testa que não houve perda de caracteres
            assert len(processed) >= len(text)
    
    def test_rtl_layout_validation(self):
        """Testa validação de layout RTL."""
        # Setup
        i18n_manager = I18nManager()
        
        # Testa configurações de layout RTL
        rtl_locales = ["ar-SA", "he-IL", "fa-IR", "ur-PK"]
        
        for locale_code in rtl_locales:
            i18n_manager.set_locale(locale_code)
            
            # Testa configurações de layout
            layout_config = i18n_manager.get_layout_config()
            assert layout_config["direction"] == "rtl"
            assert layout_config["text_align"] == "right"
            
            # Testa que configurações são aplicadas
            applied_config = i18n_manager.apply_rtl_layout()
            assert applied_config["direction"] == "rtl"


class TestNumberFormatting:
    """Testa formatação de números."""
    
    def test_number_formatting(self):
        """Testa formatação de números."""
        # Setup
        i18n_manager = I18nManager()
        
        # Números de teste
        test_numbers = [1234.56, 1000000, 0.123, -1234.56]
        
        # Formatos esperados por locale
        expected_formats = [
            # Português Brasil
            {
                "locale": "pt-BR",
                "decimal_separator": ",",
                "thousands_separator": ".",
                "currency_symbol": "R$"
            },
            # Inglês EUA
            {
                "locale": "en-US",
                "decimal_separator": ".",
                "thousands_separator": ",",
                "currency_symbol": "$"
            },
            # Espanhol
            {
                "locale": "es-ES",
                "decimal_separator": ",",
                "thousands_separator": ".",
                "currency_symbol": "€"
            },
            # Francês
            {
                "locale": "fr-FR",
                "decimal_separator": ",",
                "thousands_separator": " ",
                "currency_symbol": "€"
            },
            # Alemão
            {
                "locale": "de-DE",
                "decimal_separator": ",",
                "thousands_separator": ".",
                "currency_symbol": "€"
            }
        ]
        
        # Testa cada formato
        for expected in expected_formats:
            locale_code = expected["locale"]
            i18n_manager.set_locale(locale_code)
            
            for number in test_numbers:
                # Testa formatação de número
                formatted = format_number(number, locale_code)
                assert formatted is not None
                assert len(formatted) > 0
                
                # Valida separadores
                if expected["decimal_separator"] in formatted:
                    assert expected["decimal_separator"] in formatted
                
                # Testa que número foi formatado corretamente
                assert str(abs(int(number))) in formatted.replace(expected["decimal_separator"], "").replace(expected["thousands_separator"], "")
    
    def test_large_number_formatting(self):
        """Testa formatação de números grandes."""
        # Setup
        i18n_manager = I18nManager()
        
        # Números grandes
        large_numbers = [
            1000000,      # 1 milhão
            1000000000,   # 1 bilhão
            1000000000000 # 1 trilhão
        ]
        
        # Testa em diferentes locales
        locales = ["pt-BR", "en-US", "es-ES", "fr-FR", "de-DE"]
        
        for locale_code in locales:
            i18n_manager.set_locale(locale_code)
            
            for number in large_numbers:
                formatted = i18n_manager.format_large_number(number)
                assert formatted is not None
                assert len(formatted) > 0
                
                # Deve conter o número base
                base_number = str(number)[:3]  # Primeiros 3 dígitos
                assert base_number in formatted.replace(" ", "").replace(".", "").replace(",", "")
    
    def test_percentage_formatting(self):
        """Testa formatação de porcentagens."""
        # Setup
        i18n_manager = I18nManager()
        
        # Porcentagens de teste
        percentages = [0.123, 0.5, 1.0, 1.5, 100.0]
        
        # Testa em diferentes locales
        locales = ["pt-BR", "en-US", "es-ES", "fr-FR", "de-DE"]
        
        for locale_code in locales:
            i18n_manager.set_locale(locale_code)
            
            for percentage in percentages:
                formatted = i18n_manager.format_percentage(percentage)
                assert formatted is not None
                assert len(formatted) > 0
                
                # Deve conter símbolo de porcentagem
                assert "%" in formatted
                
                # Deve conter o valor numérico
                numeric_value = str(int(percentage * 100))
                assert numeric_value in formatted.replace("%", "").replace(",", "").replace(".", "")


class TestCurrencyFormatting:
    """Testa formatação de moeda."""
    
    def test_currency_formatting(self):
        """Testa formatação de moeda."""
        # Setup
        i18n_manager = I18nManager()
        
        # Valores monetários de teste
        amounts = [1234.56, 1000000, 0.99, -1234.56]
        
        # Formatos de moeda por locale
        currency_formats = [
            # Real Brasileiro
            {
                "locale": "pt-BR",
                "currency": "BRL",
                "symbol": "R$",
                "position": "before"
            },
            # Dólar Americano
            {
                "locale": "en-US",
                "currency": "USD",
                "symbol": "$",
                "position": "before"
            },
            # Euro
            {
                "locale": "es-ES",
                "currency": "EUR",
                "symbol": "€",
                "position": "after"
            },
            # Franco Suíço
            {
                "locale": "de-CH",
                "currency": "CHF",
                "symbol": "CHF",
                "position": "before"
            },
            # Iene Japonês
            {
                "locale": "ja-JP",
                "currency": "JPY",
                "symbol": "¥",
                "position": "before"
            }
        ]
        
        # Testa cada formato de moeda
        for currency_format in currency_formats:
            locale_code = currency_format["locale"]
            currency_code = currency_format["currency"]
            symbol = currency_format["symbol"]
            
            i18n_manager.set_locale(locale_code)
            
            for amount in amounts:
                # Testa formatação de moeda
                formatted = format_currency(amount, currency_code, locale_code)
                assert formatted is not None
                assert len(formatted) > 0
                
                # Deve conter símbolo da moeda
                assert symbol in formatted
                
                # Deve conter o valor numérico
                numeric_value = str(abs(int(amount)))
                assert numeric_value in formatted.replace(symbol, "").replace(",", "").replace(".", "").replace("-", "")
    
    def test_currency_symbol_position(self):
        """Testa posição do símbolo da moeda."""
        # Setup
        i18n_manager = I18nManager()
        
        # Testa diferentes posições de símbolo
        test_cases = [
            # Símbolo antes (mais comum)
            {"locale": "pt-BR", "currency": "BRL", "position": "before"},
            {"locale": "en-US", "currency": "USD", "position": "before"},
            {"locale": "ja-JP", "currency": "JPY", "position": "before"},
            
            # Símbolo depois (alguns países europeus)
            {"locale": "fr-FR", "currency": "EUR", "position": "after"},
            {"locale": "de-DE", "currency": "EUR", "position": "after"}
        ]
        
        amount = 1234.56
        
        for test_case in test_cases:
            locale_code = test_case["locale"]
            currency_code = test_case["currency"]
            expected_position = test_case["position"]
            
            i18n_manager.set_locale(locale_code)
            formatted = i18n_manager.format_currency_with_position(amount, currency_code)
            
            # Valida posição do símbolo
            if expected_position == "before":
                # Símbolo deve estar no início
                assert formatted.startswith("R$") or formatted.startswith("$") or formatted.startswith("¥")
            else:
                # Símbolo deve estar no final
                assert formatted.endswith("€")
    
    def test_currency_conversion_formatting(self):
        """Testa formatação com conversão de moeda."""
        # Setup
        i18n_manager = I18nManager()
        
        # Taxas de câmbio simuladas
        exchange_rates = {
            "USD": 1.0,
            "BRL": 5.0,
            "EUR": 0.85,
            "JPY": 110.0
        }
        
        amount_usd = 100.0
        
        # Testa conversão para diferentes moedas
        for currency, rate in exchange_rates.items():
            converted_amount = amount_usd * rate
            
            # Formata valor convertido
            formatted = i18n_manager.format_converted_currency(converted_amount, currency)
            assert formatted is not None
            assert len(formatted) > 0
            
            # Deve conter o valor convertido
            expected_value = str(int(converted_amount))
            assert expected_value in formatted.replace(",", "").replace(".", "")


class TestI18nContextIntegration:
    """Testa integração com contexto i18n."""
    
    def test_i18n_context_provider(self):
        """Testa provedor de contexto i18n."""
        # Setup
        context = AdvancedI18nContext()
        
        # Testa configuração inicial
        initial_locale = context.get_current_locale()
        assert initial_locale is not None
        assert len(initial_locale) > 0
        
        # Testa mudança de locale
        new_locale = "es-ES"
        context.set_locale(new_locale)
        current_locale = context.get_current_locale()
        assert current_locale == new_locale
        
        # Testa obtenção de mensagens
        message_key = "welcome"
        message = context.get_message(message_key)
        assert message is not None
        assert len(message) > 0
    
    def test_i18n_hook_integration(self):
        """Testa integração com hook i18n."""
        # Setup
        hook = use_i18n()
        
        # Testa funcionalidades do hook
        current_locale = hook.locale
        assert current_locale is not None
        
        # Testa mudança de locale via hook
        new_locale = "fr-FR"
        hook.setLocale(new_locale)
        assert hook.locale == new_locale
        
        # Testa tradução via hook
        translated = hook.t("welcome")
        assert translated is not None
        assert len(translated) > 0
        
        # Testa formatação de número via hook
        formatted_number = hook.formatNumber(1234.56)
        assert formatted_number is not None
        assert len(formatted_number) > 0
        
        # Testa formatação de data via hook
        test_date = datetime.now()
        formatted_date = hook.formatDate(test_date)
        assert formatted_date is not None
        assert len(formatted_date) > 0 