# 🌍 DETECTOR DE IDIOMA AUTOMÁTICO
# 📐 CoCoT + ToT + ReAct - Implementação Baseada em Código Real
# 🚫 PROIBIDO: Código sintético, genérico ou aleatório
# ✅ PERMITIDO: Apenas detecção baseada em padrões reais de uso
# 📅 Data/Hora: 2025-01-27T15:55:00Z
# 🎯 Prompt: Implementação de detecção automática de idioma
# 📋 Ruleset: enterprise_control_layer.yaml

"""
Detector de Idioma Automático
============================

Este módulo implementa detecção automática de idioma para
o sistema Omni Writer baseado em múltiplas fontes.

Cenários Reais Baseados em:
- Headers Accept-Language dos navegadores
- Configurações de usuário
- Preferências de sessão
- Geolocalização por IP
- Padrões de uso detectados
"""

import re
import logging
import json
import locale
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from flask import request, session, g
import geoip2.database
import geoip2.errors
import hashlib

# Configuração de logging estruturado
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Tracing ID único para rastreabilidade
TRACING_ID = "LANGUAGE_DETECTOR_20250127_001"

@dataclass
class LanguageInfo:
    """Informações sobre idioma detectado"""
    code: str
    name: str
    confidence: float
    source: str
    region: Optional[str] = None
    script: Optional[str] = None

class LanguageDetector:
    """
    Detector de idioma automático com múltiplas estratégias.
    
    Funcionalidades:
    - Detecção por headers HTTP
    - Detecção por geolocalização
    - Detecção por configurações de usuário
    - Fallback inteligente
    - Cache de detecções
    """
    
    def __init__(self):
        self.tracing_id = TRACING_ID
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Idiomas suportados baseados em uso real
        self.supported_languages = {
            'pt-BR': {
                'name': 'Português (Brasil)',
                'region': 'BR',
                'script': 'Latn',
                'fallback': 'pt'
            },
            'en-US': {
                'name': 'English (US)',
                'region': 'US',
                'script': 'Latn',
                'fallback': 'en'
            },
            'es-ES': {
                'name': 'Español (España)',
                'region': 'ES',
                'script': 'Latn',
                'fallback': 'es'
            },
            'fr-FR': {
                'name': 'Français (France)',
                'region': 'FR',
                'script': 'Latn',
                'fallback': 'fr'
            }
        }
        
        # Mapeamento de códigos de idioma para regiões
        self.language_region_mapping = {
            'pt': 'BR',  # Português -> Brasil
            'en': 'US',  # Inglês -> EUA
            'es': 'ES',  # Espanhol -> Espanha
            'fr': 'FR',  # Francês -> França
        }
        
        # Mapeamento de regiões para idiomas preferidos
        self.region_language_mapping = {
            'BR': 'pt-BR',
            'PT': 'pt-BR',
            'US': 'en-US',
            'GB': 'en-US',
            'CA': 'en-US',
            'ES': 'es-ES',
            'MX': 'es-ES',
            'AR': 'es-ES',
            'FR': 'fr-FR',
            'CA': 'en-US',  # Canadá (prioridade para inglês)
        }
        
        # Pesos de confiança para diferentes fontes
        self.confidence_weights = {
            'user_preference': 1.0,      # Configuração explícita do usuário
            'session': 0.9,              # Preferência de sessão
            'accept_language': 0.8,      # Header Accept-Language
            'geolocation': 0.7,          # Geolocalização por IP
            'browser_locale': 0.6,       # Locale do navegador
            'default': 0.5               # Idioma padrão
        }
        
        # Cache de detecções (em produção usar Redis)
        self.detection_cache = {}
        
        # Inicializa banco de dados GeoIP (opcional)
        self.geoip_reader = None
        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
            self.logger.info(f"[{self.tracing_id}] GeoIP database carregada")
        except Exception as e:
            self.logger.warning(f"[{self.tracing_id}] GeoIP database não disponível: {e}")
    
    def detect_language(self, request_context: Optional[Dict] = None) -> LanguageInfo:
        """
        Detecta idioma usando múltiplas estratégias.
        
        Args:
            request_context: Contexto da requisição (opcional)
            
        Returns:
            LanguageInfo: Informações do idioma detectado
        """
        try:
            self.logger.info(f"[{self.tracing_id}] Iniciando detecção de idioma")
            
            # Obtém contexto da requisição
            if request_context is None:
                request_context = self._get_request_context()
            
            # Tenta diferentes estratégias de detecção
            detection_results = []
            
            # 1. Preferência explícita do usuário
            user_lang = self._detect_user_preference(request_context)
            if user_lang:
                detection_results.append(user_lang)
            
            # 2. Preferência de sessão
            session_lang = self._detect_session_preference(request_context)
            if session_lang:
                detection_results.append(session_lang)
            
            # 3. Header Accept-Language
            accept_lang = self._detect_accept_language(request_context)
            if accept_lang:
                detection_results.append(accept_lang)
            
            # 4. Geolocalização
            geo_lang = self._detect_geolocation(request_context)
            if geo_lang:
                detection_results.append(geo_lang)
            
            # 5. Locale do navegador
            browser_lang = self._detect_browser_locale(request_context)
            if browser_lang:
                detection_results.append(browser_lang)
            
            # Seleciona melhor resultado
            if detection_results:
                best_result = self._select_best_detection(detection_results)
            else:
                # Fallback para idioma padrão
                best_result = LanguageInfo(
                    code='en-US',
                    name='English (US)',
                    confidence=0.5,
                    source='default'
                )
            
            # Cache do resultado
            cache_key = self._generate_cache_key(request_context)
            self.detection_cache[cache_key] = best_result
            
            self.logger.info(f"[{self.tracing_id}] Idioma detectado: {best_result.code} (confiança: {best_result.confidence})")
            return best_result
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro na detecção de idioma: {e}")
            # Fallback seguro
            return LanguageInfo(
                code='en-US',
                name='English (US)',
                confidence=0.5,
                source='error_fallback'
            )
    
    def _get_request_context(self) -> Dict[str, Any]:
        """Obtém contexto da requisição"""
        try:
            context = {
                'ip_address': self._get_client_ip(),
                'user_agent': request.headers.get('User-Agent', ''),
                'accept_language': request.headers.get('Accept-Language', ''),
                'session_id': self._get_session_id(),
                'user_id': self._get_user_id()
            }
            
            # Adiciona informações de sessão se disponível
            if hasattr(session, 'get'):
                context['session_language'] = session.get('language')
                context['session_region'] = session.get('region')
            
            return context
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao obter contexto: {e}")
            return {}
    
    def _detect_user_preference(self, context: Dict) -> Optional[LanguageInfo]:
        """Detecta preferência explícita do usuário"""
        try:
            user_id = context.get('user_id')
            if not user_id:
                return None
            
            # Em produção, buscar do banco de dados
            # Por enquanto, simula busca
            user_preferences = self._get_user_language_preference(user_id)
            
            if user_preferences and user_preferences.get('language'):
                lang_code = user_preferences['language']
                if lang_code in self.supported_languages:
                    return LanguageInfo(
                        code=lang_code,
                        name=self.supported_languages[lang_code]['name'],
                        confidence=self.confidence_weights['user_preference'],
                        source='user_preference',
                        region=self.supported_languages[lang_code]['region']
                    )
            
            return None
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro na detecção de preferência do usuário: {e}")
            return None
    
    def _detect_session_preference(self, context: Dict) -> Optional[LanguageInfo]:
        """Detecta preferência de sessão"""
        try:
            session_language = context.get('session_language')
            if session_language and session_language in self.supported_languages:
                return LanguageInfo(
                    code=session_language,
                    name=self.supported_languages[session_language]['name'],
                    confidence=self.confidence_weights['session'],
                    source='session',
                    region=self.supported_languages[session_language]['region']
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro na detecção de sessão: {e}")
            return None
    
    def _detect_accept_language(self, context: Dict) -> Optional[LanguageInfo]:
        """Detecta idioma pelo header Accept-Language"""
        try:
            accept_language = context.get('accept_language', '')
            if not accept_language:
                return None
            
            # Parse do header Accept-Language
            languages = self._parse_accept_language(accept_language)
            
            for lang, q_value in languages:
                # Normaliza código de idioma
                normalized_lang = self._normalize_language_code(lang)
                
                if normalized_lang in self.supported_languages:
                    return LanguageInfo(
                        code=normalized_lang,
                        name=self.supported_languages[normalized_lang]['name'],
                        confidence=self.confidence_weights['accept_language'] * q_value,
                        source='accept_language',
                        region=self.supported_languages[normalized_lang]['region']
                    )
                
                # Tenta fallback
                base_lang = lang.split('-')[0]
                if base_lang in self.language_region_mapping:
                    fallback_code = f"{base_lang}-{self.language_region_mapping[base_lang]}"
                    if fallback_code in self.supported_languages:
                        return LanguageInfo(
                            code=fallback_code,
                            name=self.supported_languages[fallback_code]['name'],
                            confidence=self.confidence_weights['accept_language'] * q_value * 0.8,
                            source='accept_language_fallback',
                            region=self.supported_languages[fallback_code]['region']
                        )
            
            return None
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro na detecção Accept-Language: {e}")
            return None
    
    def _detect_geolocation(self, context: Dict) -> Optional[LanguageInfo]:
        """Detecta idioma por geolocalização"""
        try:
            if not self.geoip_reader:
                return None
            
            ip_address = context.get('ip_address')
            if not ip_address or ip_address in ['127.0.0.1', 'localhost', 'unknown']:
                return None
            
            # Consulta GeoIP
            response = self.geoip_reader.country(ip_address)
            country_code = response.country.iso_code
            
            if country_code in self.region_language_mapping:
                lang_code = self.region_language_mapping[country_code]
                if lang_code in self.supported_languages:
                    return LanguageInfo(
                        code=lang_code,
                        name=self.supported_languages[lang_code]['name'],
                        confidence=self.confidence_weights['geolocation'],
                        source='geolocation',
                        region=country_code
                    )
            
            return None
            
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro na detecção geolocalização: {e}")
            return None
    
    def _detect_browser_locale(self, context: Dict) -> Optional[LanguageInfo]:
        """Detecta idioma pelo locale do navegador"""
        try:
            user_agent = context.get('user_agent', '')
            
            # Padrões comuns de locale em User-Agent
            locale_patterns = [
                r'[a-z]{2}-[A-Z]{2}',  # pt-BR, en-US, etc.
                r'[a-z]{2}_[A-Z]{2}',  # pt_BR, en_US, etc.
            ]
            
            for pattern in locale_patterns:
                match = re.search(pattern, user_agent)
                if match:
                    locale_str = match.group()
                    # Normaliza formato
                    lang_code = locale_str.replace('_', '-')
                    
                    if lang_code in self.supported_languages:
                        return LanguageInfo(
                            code=lang_code,
                            name=self.supported_languages[lang_code]['name'],
                            confidence=self.confidence_weights['browser_locale'],
                            source='browser_locale',
                            region=self.supported_languages[lang_code]['region']
                        )
            
            return None
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro na detecção de locale do navegador: {e}")
            return None
    
    def _parse_accept_language(self, accept_language: str) -> List[Tuple[str, float]]:
        """Parse do header Accept-Language"""
        try:
            languages = []
            
            # Divide por vírgulas
            parts = accept_language.split(',')
            
            for part in parts:
                part = part.strip()
                if ';' in part:
                    lang, q_part = part.split(';', 1)
                    q_value = float(q_part.split('=')[1]) if 'q=' in q_part else 1.0
                else:
                    lang = part
                    q_value = 1.0
                
                languages.append((lang, q_value))
            
            # Ordena por q-value (maior primeiro)
            languages.sort(key=lambda x: x[1], reverse=True)
            return languages
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no parse Accept-Language: {e}")
            return []
    
    def _normalize_language_code(self, lang_code: str) -> str:
        """Normaliza código de idioma"""
        try:
            # Remove espaços e converte para minúsculas
            lang_code = lang_code.strip().lower()
            
            # Converte underscore para hífen
            lang_code = lang_code.replace('_', '-')
            
            # Se tem apenas código de idioma, adiciona região padrão
            if '-' not in lang_code and lang_code in self.language_region_mapping:
                lang_code = f"{lang_code}-{self.language_region_mapping[lang_code]}"
            
            return lang_code
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro na normalização: {e}")
            return lang_code
    
    def _select_best_detection(self, detections: List[LanguageInfo]) -> LanguageInfo:
        """Seleciona melhor detecção baseado em confiança"""
        try:
            if not detections:
                return LanguageInfo(
                    code='en-US',
                    name='English (US)',
                    confidence=0.5,
                    source='default'
                )
            
            # Agrupa por código de idioma
            language_groups = {}
            for detection in detections:
                if detection.code not in language_groups:
                    language_groups[detection.code] = []
                language_groups[detection.code].append(detection)
            
            # Calcula confiança agregada para cada idioma
            best_language = None
            best_confidence = 0.0
            
            for lang_code, group_detections in language_groups.items():
                # Soma confianças ponderadas
                total_confidence = sum(d.confidence for d in group_detections)
                avg_confidence = total_confidence / len(group_detections)
                
                # Bônus para múltiplas detecções
                if len(group_detections) > 1:
                    avg_confidence *= 1.1
                
                if avg_confidence > best_confidence:
                    best_confidence = avg_confidence
                    best_language = group_detections[0]
            
            return best_language
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro na seleção de melhor detecção: {e}")
            return detections[0] if detections else LanguageInfo(
                code='en-US',
                name='English (US)',
                confidence=0.5,
                source='error_fallback'
            )
    
    def _get_client_ip(self) -> str:
        """Obtém IP do cliente"""
        try:
            for header in ['X-Forwarded-For', 'X-Real-IP', 'X-Client-IP']:
                ip = request.headers.get(header)
                if ip:
                    return ip.split(',')[0].strip()
            return request.remote_addr
        except Exception:
            return 'unknown'
    
    def _get_session_id(self) -> Optional[str]:
        """Obtém ID da sessão"""
        try:
            if hasattr(session, 'id'):
                return session.id
            elif hasattr(session, '_id'):
                return session._id
            else:
                return None
        except Exception:
            return None
    
    def _get_user_id(self) -> Optional[str]:
        """Obtém ID do usuário"""
        try:
            if hasattr(g, 'user') and g.user:
                return g.user.get('user_id')
            return None
        except Exception:
            return None
    
    def _get_user_language_preference(self, user_id: str) -> Optional[Dict]:
        """Obtém preferência de idioma do usuário (simulado)"""
        try:
            # Em produção, buscar do banco de dados
            # Por enquanto, retorna None
            return None
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao obter preferência do usuário: {e}")
            return None
    
    def _generate_cache_key(self, context: Dict) -> str:
        """Gera chave para cache"""
        try:
            key_parts = [
                context.get('ip_address', ''),
                context.get('user_agent', '')[:50],
                context.get('accept_language', ''),
                context.get('session_id', ''),
                context.get('user_id', '')
            ]
            return hashlib.md5('|'.join(key_parts).encode()).hexdigest()
        except Exception:
            return 'default'

# Instância global do detector
language_detector = LanguageDetector()

# Funções de conveniência
def detect_language(request_context: Optional[Dict] = None) -> LanguageInfo:
    """Detecta idioma automaticamente"""
    return language_detector.detect_language(request_context)

def get_supported_languages() -> Dict[str, Dict]:
    """Obtém lista de idiomas suportados"""
    return language_detector.supported_languages

def is_language_supported(lang_code: str) -> bool:
    """Verifica se idioma é suportado"""
    return lang_code in language_detector.supported_languages

def normalize_language_code(lang_code: str) -> str:
    """Normaliza código de idioma"""
    return language_detector._normalize_language_code(lang_code) 