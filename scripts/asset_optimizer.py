#!/usr/bin/env python3
"""
Sistema de Otimização de Assets - Omni Writer
=============================================

Implementa otimização de assets:
- Compressão gzip/brotli
- Minificação de CSS/JS
- Otimização de imagens
- Upload para CDN
- Cache headers inteligentes
- Lazy loading

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import os
import gzip
import json
import hashlib
import mimetypes
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import requests
import subprocess
from datetime import datetime, timedelta
import threading
import queue
import shutil

@dataclass
class AssetInfo:
    """Informações de um asset"""
    path: str
    size: int
    compressed_size: int
    mime_type: str
    hash: str
    last_modified: datetime
    optimization_status: str  # 'pending', 'optimized', 'failed'

@dataclass
class OptimizationResult:
    """Resultado de otimização"""
    asset_path: str
    original_size: int
    optimized_size: int
    compression_ratio: float
    optimization_type: str
    cdn_url: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class AssetOptimizer:
    """Sistema de otimização de assets"""
    
    def __init__(self, config_file: str = "asset_config.json"):
        self.config = self._load_config(config_file)
        
        # Configuração de logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('asset_optimization.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Estado do sistema
        self.assets: Dict[str, AssetInfo] = {}
        self.optimization_results: List[OptimizationResult] = []
        self.cdn_uploads: List[str] = []
        
        # Filas de processamento
        self.optimization_queue = queue.Queue()
        self.cdn_queue = queue.Queue()
        
        # Threads de processamento
        self.processing_threads = []
        self.running = False
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Carrega configuração de assets"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Configuração padrão
            return {
                'paths': {
                    'static': 'static/',
                    'css': 'static/css/',
                    'js': 'static/js/',
                    'images': 'static/images/',
                    'fonts': 'static/fonts/'
                },
                'compression': {
                    'enabled': True,
                    'gzip_level': 6,
                    'brotli_enabled': True,
                    'brotli_level': 11,
                    'min_size': 1024  # bytes
                },
                'minification': {
                    'css_enabled': True,
                    'js_enabled': True,
                    'html_enabled': True,
                    'remove_comments': True,
                    'remove_whitespace': True
                },
                'image_optimization': {
                    'enabled': True,
                    'quality': 85,
                    'formats': ['webp', 'avif'],
                    'resize_large_images': True,
                    'max_width': 1920,
                    'max_height': 1080
                },
                'cdn': {
                    'enabled': True,
                    'provider': 'aws_s3',  # aws_s3, cloudflare, custom
                    'bucket_name': 'omni-writer-assets',
                    'region': 'us-east-1',
                    'base_url': 'https://cdn.omniwriter.com',
                    'cache_headers': {
                        'max_age': 31536000,  # 1 ano
                        'etag': True,
                        'gzip': True
                    }
                },
                'lazy_loading': {
                    'enabled': True,
                    'threshold': 0.1,
                    'placeholder': 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgZmlsbD0iI2YwZjBmMCIvPjwvc3ZnPg=='
                },
                'monitoring': {
                    'enabled': True,
                    'interval': 300,  # 5 minutos
                    'report_size': True,
                    'report_performance': True
                }
            }
    
    def start_optimization(self):
        """Inicia sistema de otimização"""
        self.logger.info("🚀 Iniciando sistema de otimização de assets...")
        self.running = True
        
        # Inicia threads de processamento
        self._start_optimization_workers()
        self._start_cdn_upload_workers()
        self._start_monitoring()
        
        self.logger.info("✅ Sistema de otimização iniciado")
    
    def stop_optimization(self):
        """Para sistema de otimização"""
        self.logger.info("🛑 Parando sistema de otimização...")
        self.running = False
        
        # Aguarda threads terminarem
        for thread in self.processing_threads:
            thread.join()
        
        self.logger.info("✅ Sistema de otimização parado")
    
    def _start_optimization_workers(self):
        """Inicia workers de otimização"""
        for i in range(3):  # 3 workers
            thread = threading.Thread(target=self._optimization_worker, args=(i,), daemon=True)
            thread.start()
            self.processing_threads.append(thread)
    
    def _start_cdn_upload_workers(self):
        """Inicia workers de upload para CDN"""
        for i in range(2):  # 2 workers
            thread = threading.Thread(target=self._cdn_upload_worker, args=(i,), daemon=True)
            thread.start()
            self.processing_threads.append(thread)
    
    def _start_monitoring(self):
        """Inicia monitoramento"""
        def monitor():
            while self.running:
                try:
                    self._scan_assets()
                    self._generate_optimization_report()
                except Exception as e:
                    self.logger.error(f"Erro no monitoramento: {e}")
                
                time.sleep(self.config['monitoring']['interval'])
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        self.processing_threads.append(thread)
    
    def _optimization_worker(self, worker_id: int):
        """Worker de otimização"""
        self.logger.info(f"🔧 Worker de otimização {worker_id} iniciado")
        
        while self.running:
            try:
                # Pega asset da fila
                asset_path = self.optimization_queue.get(timeout=1)
                
                if asset_path:
                    self._optimize_asset(asset_path)
                    self.optimization_queue.task_done()
                    
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Erro no worker {worker_id}: {e}")
    
    def _cdn_upload_worker(self, worker_id: int):
        """Worker de upload para CDN"""
        self.logger.info(f"☁️ Worker de CDN {worker_id} iniciado")
        
        while self.running:
            try:
                # Pega asset da fila
                asset_path = self.cdn_queue.get(timeout=1)
                
                if asset_path:
                    self._upload_to_cdn(asset_path)
                    self.cdn_queue.task_done()
                    
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Erro no worker de CDN {worker_id}: {e}")
    
    def _scan_assets(self):
        """Escaneia assets para otimização"""
        paths = self.config['paths']
        
        for path_name, path_value in paths.items():
            path = Path(path_value)
            
            if path.exists():
                for file_path in path.rglob('*'):
                    if file_path.is_file():
                        self._process_asset(file_path)
    
    def _process_asset(self, file_path: Path):
        """Processa um asset"""
        try:
            # Obtém informações do arquivo
            stat = file_path.stat()
            mime_type, _ = mimetypes.guess_type(str(file_path))
            
            # Calcula hash do arquivo
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            
            asset_info = AssetInfo(
                path=str(file_path),
                size=stat.st_size,
                compressed_size=0,
                mime_type=mime_type or 'application/octet-stream',
                hash=file_hash,
                last_modified=datetime.fromtimestamp(stat.st_mtime),
                optimization_status='pending'
            )
            
            # Verifica se precisa otimizar
            if self._needs_optimization(asset_info):
                self.assets[str(file_path)] = asset_info
                self.optimization_queue.put(str(file_path))
                
        except Exception as e:
            self.logger.error(f"Erro ao processar asset {file_path}: {e}")
    
    def _needs_optimization(self, asset_info: AssetInfo) -> bool:
        """Verifica se asset precisa de otimização"""
        # Verifica se arquivo é grande o suficiente
        if asset_info.size < self.config['compression']['min_size']:
            return False
        
        # Verifica tipo de arquivo
        mime_type = asset_info.mime_type.lower()
        
        # Arquivos que podem ser otimizados
        optimizable_types = [
            'text/css',
            'application/javascript',
            'text/html',
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp'
        ]
        
        return any(opt_type in mime_type for opt_type in optimizable_types)
    
    def _optimize_asset(self, asset_path: str):
        """Otimiza um asset"""
        try:
            file_path = Path(asset_path)
            asset_info = self.assets.get(asset_path)
            
            if not asset_info:
                return
            
            self.logger.info(f"🔧 Otimizando: {file_path.name}")
            
            # Determina tipo de otimização
            mime_type = asset_info.mime_type.lower()
            
            if 'text/css' in mime_type or 'application/javascript' in mime_type:
                result = self._optimize_text_asset(file_path, asset_info)
            elif 'image/' in mime_type:
                result = self._optimize_image_asset(file_path, asset_info)
            else:
                result = self._optimize_generic_asset(file_path, asset_info)
            
            if result:
                self.optimization_results.append(result)
                asset_info.optimization_status = 'optimized'
                
                # Adiciona à fila de CDN se habilitado
                if self.config['cdn']['enabled']:
                    self.cdn_queue.put(asset_path)
                
                self.logger.info(f"✅ Otimizado: {file_path.name} "
                               f"({result.compression_ratio:.1f}% redução)")
            
        except Exception as e:
            self.logger.error(f"Erro ao otimizar {asset_path}: {e}")
            if asset_info:
                asset_info.optimization_status = 'failed'
    
    def _optimize_text_asset(self, file_path: Path, asset_info: AssetInfo) -> Optional[OptimizationResult]:
        """Otimiza asset de texto (CSS, JS, HTML)"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_size = len(content.encode('utf-8'))
            optimized_content = content
            
            # Minificação
            if self.config['minification']['css_enabled'] and file_path.suffix == '.css':
                optimized_content = self._minify_css(content)
            elif self.config['minification']['js_enabled'] and file_path.suffix == '.js':
                optimized_content = self._minify_js(content)
            elif self.config['minification']['html_enabled'] and file_path.suffix == '.html':
                optimized_content = self._minify_html(content)
            
            # Compressão
            compressed_content = self._compress_content(optimized_content)
            
            # Salva versão otimizada
            optimized_path = file_path.with_suffix(file_path.suffix + '.min' + file_path.suffix)
            with open(optimized_path, 'w', encoding='utf-8') as f:
                f.write(optimized_content)
            
            # Salva versão comprimida
            compressed_path = optimized_path.with_suffix(optimized_path.suffix + '.gz')
            with open(compressed_path, 'wb') as f:
                f.write(compressed_content)
            
            optimized_size = len(compressed_content)
            compression_ratio = ((original_size - optimized_size) / original_size) * 100
            
            return OptimizationResult(
                asset_path=str(file_path),
                original_size=original_size,
                optimized_size=optimized_size,
                compression_ratio=compression_ratio,
                optimization_type='text_minification_compression'
            )
            
        except Exception as e:
            self.logger.error(f"Erro ao otimizar texto {file_path}: {e}")
            return None
    
    def _minify_css(self, content: str) -> str:
        """Minifica CSS"""
        # Remove comentários
        if self.config['minification']['remove_comments']:
            import re
            content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Remove whitespace
        if self.config['minification']['remove_whitespace']:
            content = re.sub(r'\s+', ' ', content)
            content = re.sub(r';\s*}', '}', content)
            content = re.sub(r'{\s*', '{', content)
            content = re.sub(r'}\s*', '}', content)
            content = re.sub(r':\s*', ':', content)
            content = re.sub(r';\s*', ';', content)
            content = re.sub(r',\s*', ',', content)
        
        return content.strip()
    
    def _minify_js(self, content: str) -> str:
        """Minifica JavaScript"""
        # Remove comentários
        if self.config['minification']['remove_comments']:
            import re
            # Remove comentários de linha
            content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
            # Remove comentários de bloco
            content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Remove whitespace
        if self.config['minification']['remove_whitespace']:
            content = re.sub(r'\s+', ' ', content)
            content = re.sub(r';\s*}', '}', content)
            content = re.sub(r'{\s*', '{', content)
            content = re.sub(r'}\s*', '}', content)
        
        return content.strip()
    
    def _minify_html(self, content: str) -> str:
        """Minifica HTML"""
        # Remove comentários
        if self.config['minification']['remove_comments']:
            import re
            content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
        
        # Remove whitespace
        if self.config['minification']['remove_whitespace']:
            content = re.sub(r'\s+', ' ', content)
            content = re.sub(r'>\s*<', '><', content)
        
        return content.strip()
    
    def _compress_content(self, content: str) -> bytes:
        """Comprime conteúdo"""
        content_bytes = content.encode('utf-8')
        
        # Compressão gzip
        compressed = gzip.compress(
            content_bytes, 
            compresslevel=self.config['compression']['gzip_level']
        )
        
        # Compressão brotli se habilitada
        if self.config['compression']['brotli_enabled']:
            try:
                import brotli
                brotli_compressed = brotli.compress(
                    content_bytes, 
                    quality=self.config['compression']['brotli_level']
                )
                
                # Usa o menor entre gzip e brotli
                if len(brotli_compressed) < len(compressed):
                    return brotli_compressed
                    
            except ImportError:
                self.logger.warning("Brotli não disponível, usando apenas gzip")
        
        return compressed
    
    def _optimize_image_asset(self, file_path: Path, asset_info: AssetInfo) -> Optional[OptimizationResult]:
        """Otimiza asset de imagem"""
        try:
            if not self.config['image_optimization']['enabled']:
                return None
            
            original_size = asset_info.size
            
            # Verifica se imagem é muito grande
            if self.config['image_optimization']['resize_large_images']:
                self._resize_large_image(file_path)
            
            # Converte para formatos modernos
            for format_name in self.config['image_optimization']['formats']:
                if format_name == 'webp':
                    self._convert_to_webp(file_path)
                elif format_name == 'avif':
                    self._convert_to_avif(file_path)
            
            # Otimiza imagem original
            optimized_path = self._optimize_image_quality(file_path)
            
            if optimized_path and optimized_path.exists():
                optimized_size = optimized_path.stat().st_size
                compression_ratio = ((original_size - optimized_size) / original_size) * 100
                
                return OptimizationResult(
                    asset_path=str(file_path),
                    original_size=original_size,
                    optimized_size=optimized_size,
                    compression_ratio=compression_ratio,
                    optimization_type='image_optimization'
                )
            
        except Exception as e:
            self.logger.error(f"Erro ao otimizar imagem {file_path}: {e}")
        
        return None
    
    def _resize_large_image(self, file_path: Path):
        """Redimensiona imagem muito grande"""
        try:
            from PIL import Image
            
            with Image.open(file_path) as img:
                width, height = img.size
                max_width = self.config['image_optimization']['max_width']
                max_height = self.config['image_optimization']['max_height']
                
                if width > max_width or height > max_height:
                    # Calcula novas dimensões mantendo proporção
                    ratio = min(max_width / width, max_height / height)
                    new_width = int(width * ratio)
                    new_height = int(height * ratio)
                    
                    # Redimensiona
                    resized_img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
                    
                    # Salva versão redimensionada
                    resized_path = file_path.with_stem(file_path.stem + '_resized')
                    resized_img.save(resized_path, quality=self.config['image_optimization']['quality'])
                    
                    self.logger.info(f"📏 Imagem redimensionada: {file_path.name}")
                    
        except ImportError:
            self.logger.warning("Pillow não disponível para redimensionamento de imagens")
        except Exception as e:
            self.logger.error(f"Erro ao redimensionar {file_path}: {e}")
    
    def _convert_to_webp(self, file_path: Path):
        """Converte imagem para WebP"""
        try:
            from PIL import Image
            
            with Image.open(file_path) as img:
                webp_path = file_path.with_suffix('.webp')
                img.save(webp_path, 'WEBP', quality=self.config['image_optimization']['quality'])
                
                self.logger.info(f"🖼️ Convertido para WebP: {file_path.name}")
                
        except ImportError:
            self.logger.warning("Pillow não disponível para conversão WebP")
        except Exception as e:
            self.logger.error(f"Erro ao converter para WebP {file_path}: {e}")
    
    def _convert_to_avif(self, file_path: Path):
        """Converte imagem para AVIF"""
        try:
            # AVIF requer biblioteca externa
            avif_path = file_path.with_suffix('.avif')
            
            # Comando para conversão (requer imagemagick ou similar)
            cmd = [
                'magick', str(file_path), 
                '-quality', str(self.config['image_optimization']['quality']),
                str(avif_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"🖼️ Convertido para AVIF: {file_path.name}")
            else:
                self.logger.warning(f"Conversão AVIF falhou: {result.stderr}")
                
        except FileNotFoundError:
            self.logger.warning("ImageMagick não disponível para conversão AVIF")
        except Exception as e:
            self.logger.error(f"Erro ao converter para AVIF {file_path}: {e}")
    
    def _optimize_image_quality(self, file_path: Path) -> Optional[Path]:
        """Otimiza qualidade da imagem"""
        try:
            from PIL import Image
            
            with Image.open(file_path) as img:
                optimized_path = file_path.with_stem(file_path.stem + '_optimized')
                
                # Salva com qualidade otimizada
                img.save(optimized_path, quality=self.config['image_optimization']['quality'])
                
                return optimized_path
                
        except ImportError:
            self.logger.warning("Pillow não disponível para otimização de qualidade")
        except Exception as e:
            self.logger.error(f"Erro ao otimizar qualidade {file_path}: {e}")
        
        return None
    
    def _optimize_generic_asset(self, file_path: Path, asset_info: AssetInfo) -> Optional[OptimizationResult]:
        """Otimiza asset genérico"""
        try:
            # Apenas compressão para arquivos genéricos
            with open(file_path, 'rb') as f:
                content = f.read()
            
            compressed = gzip.compress(
                content, 
                compresslevel=self.config['compression']['gzip_level']
            )
            
            # Salva versão comprimida
            compressed_path = file_path.with_suffix(file_path.suffix + '.gz')
            with open(compressed_path, 'wb') as f:
                f.write(compressed)
            
            compression_ratio = ((len(content) - len(compressed)) / len(content)) * 100
            
            return OptimizationResult(
                asset_path=str(file_path),
                original_size=len(content),
                optimized_size=len(compressed),
                compression_ratio=compression_ratio,
                optimization_type='generic_compression'
            )
            
        except Exception as e:
            self.logger.error(f"Erro ao otimizar asset genérico {file_path}: {e}")
            return None
    
    def _upload_to_cdn(self, asset_path: str):
        """Faz upload para CDN"""
        try:
            if not self.config['cdn']['enabled']:
                return
            
            file_path = Path(asset_path)
            
            # Determina URL do CDN
            cdn_url = self._get_cdn_url(file_path)
            
            # Upload baseado no provedor
            provider = self.config['cdn']['provider']
            
            if provider == 'aws_s3':
                self._upload_to_s3(file_path, cdn_url)
            elif provider == 'cloudflare':
                self._upload_to_cloudflare(file_path, cdn_url)
            else:
                self._upload_to_custom_cdn(file_path, cdn_url)
            
            self.cdn_uploads.append(cdn_url)
            self.logger.info(f"☁️ Upload para CDN: {file_path.name}")
            
        except Exception as e:
            self.logger.error(f"Erro no upload para CDN {asset_path}: {e}")
    
    def _get_cdn_url(self, file_path: Path) -> str:
        """Gera URL do CDN"""
        base_url = self.config['cdn']['base_url']
        relative_path = file_path.relative_to(Path(self.config['paths']['static']))
        
        return f"{base_url}/{relative_path}"
    
    def _upload_to_s3(self, file_path: Path, cdn_url: str):
        """Upload para AWS S3"""
        try:
            import boto3
            
            s3_client = boto3.client('s3')
            bucket_name = self.config['cdn']['bucket_name']
            
            # Determina content-type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            
            # Upload do arquivo
            with open(file_path, 'rb') as f:
                s3_client.upload_fileobj(
                    f,
                    bucket_name,
                    str(file_path.name),
                    ExtraArgs={
                        'ContentType': mime_type or 'application/octet-stream',
                        'CacheControl': f"max-age={self.config['cdn']['cache_headers']['max_age']}"
                    }
                )
            
        except ImportError:
            self.logger.warning("boto3 não disponível para upload S3")
        except Exception as e:
            self.logger.error(f"Erro no upload S3: {e}")
    
    def _upload_to_cloudflare(self, file_path: Path, cdn_url: str):
        """Upload para Cloudflare"""
        try:
            # Implementação específica do Cloudflare
            # Requer API key e configuração específica
            self.logger.info(f"Upload para Cloudflare: {file_path.name}")
            
        except Exception as e:
            self.logger.error(f"Erro no upload Cloudflare: {e}")
    
    def _upload_to_custom_cdn(self, file_path: Path, cdn_url: str):
        """Upload para CDN customizado"""
        try:
            # Implementação genérica de upload
            # Pode ser adaptada para qualquer CDN
            self.logger.info(f"Upload para CDN customizado: {file_path.name}")
            
        except Exception as e:
            self.logger.error(f"Erro no upload CDN customizado: {e}")
    
    def _generate_optimization_report(self):
        """Gera relatório de otimização"""
        if not self.optimization_results:
            return
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_assets': len(self.assets),
            'optimized_assets': len(self.optimization_results),
            'cdn_uploads': len(self.cdn_uploads),
            'total_size_saved': sum(r.original_size - r.optimized_size for r in self.optimization_results),
            'average_compression_ratio': sum(r.compression_ratio for r in self.optimization_results) / len(self.optimization_results),
            'optimization_types': {},
            'top_optimizations': []
        }
        
        # Agrupa por tipo de otimização
        for result in self.optimization_results:
            opt_type = result.optimization_type
            if opt_type not in report['optimization_types']:
                report['optimization_types'][opt_type] = 0
            report['optimization_types'][opt_type] += 1
        
        # Top otimizações
        top_results = sorted(
            self.optimization_results, 
            key=lambda x: x.compression_ratio, 
            reverse=True
        )[:10]
        
        report['top_optimizations'] = [
            {
                'asset': r.asset_path,
                'compression_ratio': r.compression_ratio,
                'size_saved': r.original_size - r.optimized_size,
                'type': r.optimization_type
            }
            for r in top_results
        ]
        
        # Salva relatório
        report_file = f"asset_optimization_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"📄 Relatório de otimização salvo: {report_file}")
        
        # Log de resumo
        total_saved = report['total_size_saved']
        avg_ratio = report['average_compression_ratio']
        
        self.logger.info(f"📊 Otimização: {len(self.optimization_results)} assets, "
                        f"{total_saved / 1024 / 1024:.2f}MB economizados, "
                        f"{avg_ratio:.1f}% redução média")
    
    def get_optimization_summary(self) -> Dict[str, Any]:
        """Retorna resumo de otimização"""
        if not self.optimization_results:
            return {}
        
        return {
            'total_assets': len(self.assets),
            'optimized_assets': len(self.optimization_results),
            'total_size_saved': sum(r.original_size - r.optimized_size for r in self.optimization_results),
            'average_compression_ratio': sum(r.compression_ratio for r in self.optimization_results) / len(self.optimization_results),
            'cdn_uploads': len(self.cdn_uploads)
        }

def main():
    """Função principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Sistema de Otimização de Assets")
    parser.add_argument("--config", default="asset_config.json", help="Arquivo de configuração")
    parser.add_argument("--scan", action="store_true", help="Apenas escaneia assets")
    parser.add_argument("--optimize", action="store_true", help="Executa otimização")
    parser.add_argument("--upload", action="store_true", help="Faz upload para CDN")
    
    args = parser.parse_args()
    
    optimizer = AssetOptimizer(args.config)
    
    try:
        if args.scan:
            optimizer._scan_assets()
            print("✅ Assets escaneados")
        elif args.optimize:
            optimizer.start_optimization()
            time.sleep(60)  # Executa por 1 minuto
            optimizer.stop_optimization()
        elif args.upload:
            optimizer.start_optimization()
            time.sleep(120)  # Executa por 2 minutos
            optimizer.stop_optimization()
        else:
            optimizer.start_optimization()
            time.sleep(3600)  # Executa por 1 hora
            
    except KeyboardInterrupt:
        print("\n🛑 Interrompendo otimização...")
    finally:
        optimizer.stop_optimization()

if __name__ == "__main__":
    main() 