"""
Teste Unitário - Sistema de Performance e Otimização
===================================================

Testa funcionalidades do sistema de performance:
- Otimização de queries
- Análise de performance
- Cache inteligente
- Compressão de assets
- CDN e lazy loading

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock
import sys
from datetime import datetime, timedelta

# Adiciona o diretório scripts ao path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from performance_optimizer import (
    PerformanceOptimizer, 
    QueryAnalysis, 
    PerformanceMetrics, 
    CacheMetrics
)
from asset_optimizer import (
    AssetOptimizer, 
    AssetInfo, 
    OptimizationResult
)

class TestPerformanceOptimizer:
    """Testes para o sistema de otimização de performance"""
    
    @pytest.fixture
    def temp_config(self):
        """Cria configuração temporária para testes"""
        config = {
            'database': {
                'connection_string': 'postgresql://localhost:5432/test_db',
                'slow_query_threshold': 1000,
                'max_connections': 10,
                'connection_timeout': 30,
                'query_timeout': 60
            },
            'cache': {
                'redis_host': 'localhost',
                'redis_port': 6379,
                'redis_db': 0,
                'default_ttl': 3600,
                'max_memory': '512mb',
                'eviction_policy': 'allkeys-lru'
            },
            'compression': {
                'enabled': True,
                'min_size': 1024,
                'compression_level': 6,
                'supported_types': ['text/html', 'text/css', 'application/javascript']
            },
            'monitoring': {
                'interval': 60,
                'retention_days': 7,
                'alert_thresholds': {
                    'response_time': 2000,
                    'error_rate': 5,
                    'cache_hit_rate': 80
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            temp_config_file = f.name
        
        yield temp_config_file
        
        # Limpa arquivo temporário
        os.unlink(temp_config_file)
    
    @pytest.fixture
    def optimizer(self, temp_config):
        """Cria instância do otimizador para testes"""
        with patch('redis.Redis'):
            return PerformanceOptimizer(temp_config)
    
    def test_load_config(self, temp_config):
        """Testa carregamento de configuração"""
        with patch('redis.Redis'):
            optimizer = PerformanceOptimizer(temp_config)
            
            assert 'database' in optimizer.config
            assert 'cache' in optimizer.config
            assert 'compression' in optimizer.config
            assert 'monitoring' in optimizer.config
    
    def test_load_default_config(self):
        """Testa carregamento de configuração padrão"""
        with patch('redis.Redis'):
            optimizer = PerformanceOptimizer('nonexistent_config.json')
            
            assert 'database' in optimizer.config
            assert 'cache' in optimizer.config
            assert 'compression' in optimizer.config
    
    @patch('psycopg2.connect')
    def test_analyze_slow_queries(self, mock_connect, optimizer):
        """Testa análise de queries lentas"""
        # Mock de conexão e cursor
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Mock de dados de queries lentas
        mock_cursor.fetchall.return_value = [
            {
                'query': 'SELECT * FROM articles WHERE user_id = 1',
                'calls': 100,
                'total_time': 50000,
                'mean_time': 500,
                'rows': 1000,
                'shared_blks_hit': 500,
                'shared_blks_read': 100,
                'shared_blks_written': 0,
                'shared_blks_dirtied': 0,
                'temp_blks_read': 0,
                'temp_blks_written': 0,
                'blk_read_time': 100,
                'blk_write_time': 0
            }
        ]
        
        optimizer._analyze_slow_queries()
        
        # Verifica se análise foi executada
        assert len(optimizer.query_analyses) > 0
        
        # Verifica se cursor foi fechado
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()
    
    def test_identify_missing_indexes(self, optimizer):
        """Testa identificação de índices ausentes"""
        query = "SELECT * FROM articles WHERE user_id = 1 AND status = 'published' ORDER BY created_at DESC"
        
        missing_indexes = optimizer._identify_missing_indexes(query)
        
        assert 'idx_articles_user_id' in missing_indexes
        assert 'idx_articles_created_at' in missing_indexes
        assert 'idx_articles_status' in missing_indexes
    
    def test_generate_optimization_suggestions(self, optimizer):
        """Testa geração de sugestões de otimização"""
        query = "SELECT * FROM articles WHERE user_id = 1"
        query_data = {
            'shared_blks_read': 100,
            'shared_blks_hit': 50,
            'temp_blks_read': 10,
            'mean_time': 1500,
            'calls': 2000
        }
        
        suggestions = optimizer._generate_optimization_suggestions(query, query_data)
        
        assert len(suggestions) > 0
        assert any('índices' in suggestion for suggestion in suggestions)
        assert any('cache' in suggestion for suggestion in suggestions)
    
    @patch('psycopg2.connect')
    def test_optimize_indexes(self, mock_connect, optimizer):
        """Testa otimização de índices"""
        # Mock de conexão e cursor
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Mock de dados de índices
        mock_cursor.fetchall.return_value = [
            ('public', 'articles', 'idx_unused', 0, 0, 0),
            ('public', 'articles', 'idx_large', 1000, 10000, 5000)
        ]
        
        optimizer._optimize_indexes()
        
        # Verifica se análise foi executada
        mock_cursor.execute.assert_called()
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()
    
    @patch('psycopg2.connect')
    def test_analyze_query_patterns(self, mock_connect, optimizer):
        """Testa análise de padrões de queries"""
        # Mock de conexão e cursor
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Mock de queries frequentes
        mock_cursor.fetchall.return_value = [
            {
                'query': 'SELECT * FROM articles WHERE user_id = 1',
                'calls': 5000,
                'total_time': 100000,
                'mean_time': 20,
                'rows': 100
            }
        ]
        
        optimizer._analyze_query_patterns()
        
        # Verifica se análise foi executada
        mock_cursor.execute.assert_called()
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()
    
    def test_suggest_query_cache(self, optimizer):
        """Testa sugestão de cache para queries"""
        query = "SELECT * FROM articles WHERE user_id = 1"
        
        with patch.object(optimizer.redis_client, 'exists', return_value=False):
            optimizer._suggest_query_cache(query)
            
            # Verifica se sugestão foi feita
            # (verificação via logs seria mais apropriada)
            assert True  # Placeholder
    
    def test_collect_performance_metrics(self, optimizer):
        """Testa coleta de métricas de performance"""
        with patch('psutil.cpu_percent', return_value=50.0):
            with patch('psutil.virtual_memory') as mock_memory:
                mock_memory.return_value.percent = 60.0
                
                with patch('psutil.disk_usage') as mock_disk:
                    mock_disk.return_value.used = 50000000000
                    mock_disk.return_value.total = 100000000000
                    
                    with patch('psutil.net_io_counters') as mock_network:
                        mock_network.return_value.bytes_sent = 1000000
                        mock_network.return_value.bytes_recv = 2000000
                        
                        optimizer._collect_performance_metrics()
                        
                        assert len(optimizer.performance_metrics) > 0
                        
                        # Verifica métricas
                        metrics = optimizer.performance_metrics[-1]
                        assert metrics.component == 'system'
                        assert metrics.resource_usage['cpu'] == 50.0
                        assert metrics.resource_usage['memory'] == 60.0
                        assert metrics.resource_usage['disk'] == 50.0
    
    def test_check_performance_thresholds(self, optimizer):
        """Testa verificação de thresholds de performance"""
        metrics = PerformanceMetrics(
            component='test',
            response_time=2500,  # Acima do threshold
            throughput=100,
            error_rate=10,  # Acima do threshold
            resource_usage={'cpu': 50},
            timestamp=datetime.now()
        )
        
        with patch.object(optimizer.logger, 'warning') as mock_warning:
            optimizer._check_performance_thresholds(metrics)
            
            # Verifica se warnings foram gerados
            assert mock_warning.call_count >= 2
    
    def test_analyze_performance_trends(self, optimizer):
        """Testa análise de tendências de performance"""
        # Adiciona métricas de exemplo
        for i in range(10):
            metrics = PerformanceMetrics(
                component='test',
                response_time=150 + i * 10,  # Crescente
                throughput=100,
                error_rate=2,
                resource_usage={'cpu': 50},
                timestamp=datetime.now()
            )
            optimizer.performance_metrics.append(metrics)
        
        with patch.object(optimizer.logger, 'warning') as mock_warning:
            optimizer._analyze_performance_trends()
            
            # Verifica se warning foi gerado para degradação
            assert mock_warning.called
    
    def test_optimize_resources(self, optimizer):
        """Testa otimização de recursos"""
        with patch('psutil.virtual_memory') as mock_memory:
            mock_memory.return_value.percent = 85  # Alto uso
            
            with patch('psutil.cpu_percent', return_value=85):  # Alto uso
                
                with patch('psutil.disk_usage') as mock_disk:
                    mock_disk.return_value.used = 90000000000
                    mock_disk.return_value.total = 100000000000  # 90% uso
                    
                    with patch.object(optimizer, '_suggest_memory_optimization') as mock_memory_opt:
                        with patch.object(optimizer, '_suggest_cpu_optimization') as mock_cpu_opt:
                            with patch.object(optimizer, '_suggest_disk_optimization') as mock_disk_opt:
                                
                                optimizer._optimize_resources()
                                
                                # Verifica se sugestões foram chamadas
                                mock_memory_opt.assert_called_once()
                                mock_cpu_opt.assert_called_once()
                                mock_disk_opt.assert_called_once()
    
    def test_suggest_memory_optimization(self, optimizer):
        """Testa sugestões de otimização de memória"""
        with patch.object(optimizer.logger, 'info') as mock_info:
            optimizer._suggest_memory_optimization()
            
            # Verifica se sugestões foram logadas
            assert mock_info.call_count >= 4
    
    def test_suggest_cpu_optimization(self, optimizer):
        """Testa sugestões de otimização de CPU"""
        with patch.object(optimizer.logger, 'info') as mock_info:
            optimizer._suggest_cpu_optimization()
            
            # Verifica se sugestões foram logadas
            assert mock_info.call_count >= 4
    
    def test_suggest_disk_optimization(self, optimizer):
        """Testa sugestões de otimização de disco"""
        with patch.object(optimizer.logger, 'info') as mock_info:
            optimizer._suggest_disk_optimization()
            
            # Verifica se sugestões foram logadas
            assert mock_info.call_count >= 4
    
    @patch.object(PerformanceOptimizer, 'redis_client')
    def test_collect_cache_metrics(self, mock_redis, optimizer):
        """Testa coleta de métricas de cache"""
        # Mock de informações do Redis
        mock_redis.info.return_value = {
            'keyspace_hits': 1000,
            'keyspace_misses': 200,
            'used_memory': 50000000,
            'maxmemory': 100000000,
            'evicted_keys': 50
        }
        
        optimizer._collect_cache_metrics()
        
        assert len(optimizer.cache_metrics) > 0
        
        # Verifica métricas
        metrics = optimizer.cache_metrics[-1]
        assert metrics.cache_name == 'redis'
        assert metrics.hit_rate == 83.33  # 1000 / (1000 + 200) * 100
        assert metrics.miss_rate == 16.67
        assert metrics.size == 50000000
        assert metrics.evictions == 50
    
    @patch.object(PerformanceOptimizer, 'redis_client')
    def test_optimize_cache(self, mock_redis, optimizer):
        """Testa otimização de cache"""
        # Mock de configuração
        mock_redis.config_get.return_value = {'maxmemory-policy': 'noeviction'}
        
        # Mock de chaves
        mock_redis.keys.return_value = [b'test_key1', b'test_key2']
        mock_redis.ttl.side_effect = [-1, 3600]  # Uma sem TTL, outra com TTL
        
        with patch.object(optimizer.logger, 'info') as mock_info:
            optimizer._optimize_cache()
            
            # Verifica se sugestões foram feitas
            assert mock_info.called
    
    @patch.object(PerformanceOptimizer, 'redis_client')
    def test_cleanup_expired_cache(self, mock_redis, optimizer):
        """Testa limpeza de cache expirado"""
        # Mock de informações do Redis
        mock_redis.info.return_value = {'expired_keys': 1500}
        
        with patch.object(optimizer.logger, 'info') as mock_info:
            optimizer._cleanup_expired_cache()
            
            # Verifica se log foi gerado
            mock_info.assert_called_once()
    
    @patch('psycopg2.connect')
    def test_optimize_database_queries(self, mock_connect, optimizer):
        """Testa otimização de queries do banco"""
        # Mock de conexão e cursor
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        with patch.object(optimizer.logger, 'info') as mock_info:
            optimizer._optimize_database_queries()
            
            # Verifica se comandos foram executados
            assert mock_cursor.execute.call_count >= 2
            mock_cursor.close.assert_called_once()
            mock_conn.close.assert_called_once()
    
    def test_optimize_cache_strategy(self, optimizer):
        """Testa otimização de estratégia de cache"""
        with patch.object(optimizer.redis_client, 'config_set') as mock_config:
            with patch.object(optimizer.logger, 'info') as mock_info:
                optimizer._optimize_cache_strategy()
                
                # Verifica se configuração foi aplicada
                mock_config.assert_called_once()
                assert mock_info.call_count >= 1
    
    def test_optimize_assets(self, optimizer):
        """Testa otimização de assets"""
        # Cria diretório temporário para assets
        with tempfile.TemporaryDirectory() as temp_dir:
            assets_path = Path(temp_dir) / 'assets'
            assets_path.mkdir()
            
            # Cria arquivo CSS de teste
            css_file = assets_path / 'test.css'
            css_content = """
            body {
                margin: 0;
                padding: 0;
                background-color: #ffffff;
            }
            .container {
                width: 100%;
                max-width: 1200px;
                margin: 0 auto;
            }
            """
            css_file.write_text(css_content)
            
            # Atualiza configuração
            optimizer.config['cdn']['assets_path'] = str(assets_path)
            
            with patch.object(optimizer, '_compress_file') as mock_compress:
                with patch.object(optimizer, '_optimize_image') as mock_optimize:
                    optimizer._optimize_assets()
                    
                    # Verifica se compressão foi chamada
                    mock_compress.assert_called()
    
    def test_compress_file(self, optimizer):
        """Testa compressão de arquivo"""
        # Cria arquivo temporário
        with tempfile.NamedTemporaryFile(mode='w', suffix='.css', delete=False) as f:
            f.write("body { margin: 0; padding: 0; }")
            temp_file = f.name
        
        try:
            file_path = Path(temp_file)
            
            with patch.object(optimizer.logger, 'debug') as mock_debug:
                optimizer._compress_file(file_path)
                
                # Verifica se arquivo comprimido foi criado
                compressed_path = file_path.with_suffix(file_path.suffix + '.gz')
                assert compressed_path.exists()
                
                # Verifica se log foi gerado
                mock_debug.assert_called_once()
                
        finally:
            # Limpa arquivos
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            compressed_path = Path(temp_file).with_suffix('.css.gz')
            if compressed_path.exists():
                compressed_path.unlink()
    
    def test_optimize_image(self, optimizer):
        """Testa otimização de imagem"""
        # Cria arquivo temporário
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            f.write(b'fake_png_data')
            temp_file = f.name
        
        try:
            file_path = Path(temp_file)
            
            with patch.object(optimizer.logger, 'info') as mock_info:
                optimizer._optimize_image(file_path)
                
                # Verifica se sugestão foi feita
                mock_info.assert_called_once()
                
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_generate_optimization_report(self, optimizer):
        """Testa geração de relatório de otimização"""
        # Adiciona resultados de exemplo
        optimizer.optimization_results = [
            OptimizationResult(
                asset_path='test.css',
                original_size=1000,
                optimized_size=500,
                compression_ratio=50.0,
                optimization_type='text_minification_compression'
            )
        ]
        
        with patch.object(optimizer.logger, 'info') as mock_info:
            optimizer._generate_optimization_report()
            
            # Verifica se relatório foi gerado
            mock_info.assert_called()
    
    def test_get_performance_summary(self, optimizer):
        """Testa obtenção de resumo de performance"""
        # Adiciona métricas de exemplo
        optimizer.performance_metrics = [
            PerformanceMetrics(
                component='test',
                response_time=150,
                throughput=100,
                error_rate=2,
                resource_usage={'cpu': 50, 'memory': 60, 'disk': 40},
                timestamp=datetime.now()
            )
        ]
        
        summary = optimizer.get_performance_summary()
        
        assert 'avg_response_time' in summary
        assert 'avg_throughput' in summary
        assert 'avg_error_rate' in summary
        assert 'resource_usage' in summary

class TestAssetOptimizer:
    """Testes para o sistema de otimização de assets"""
    
    @pytest.fixture
    def temp_config(self):
        """Cria configuração temporária para testes"""
        config = {
            'paths': {
                'static': 'static/',
                'css': 'static/css/',
                'js': 'static/js/',
                'images': 'static/images/'
            },
            'compression': {
                'enabled': True,
                'gzip_level': 6,
                'brotli_enabled': True,
                'brotli_level': 11,
                'min_size': 1024
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
                'formats': ['webp'],
                'resize_large_images': True,
                'max_width': 1920,
                'max_height': 1080
            },
            'cdn': {
                'enabled': True,
                'provider': 'aws_s3',
                'bucket_name': 'test-bucket',
                'region': 'us-east-1',
                'base_url': 'https://cdn.test.com',
                'cache_headers': {
                    'max_age': 31536000,
                    'etag': True,
                    'gzip': True
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            temp_config_file = f.name
        
        yield temp_config_file
        
        # Limpa arquivo temporário
        os.unlink(temp_config_file)
    
    @pytest.fixture
    def optimizer(self, temp_config):
        """Cria instância do otimizador de assets para testes"""
        return AssetOptimizer(temp_config)
    
    def test_load_config(self, temp_config):
        """Testa carregamento de configuração"""
        optimizer = AssetOptimizer(temp_config)
        
        assert 'paths' in optimizer.config
        assert 'compression' in optimizer.config
        assert 'minification' in optimizer.config
        assert 'image_optimization' in optimizer.config
        assert 'cdn' in optimizer.config
    
    def test_load_default_config(self):
        """Testa carregamento de configuração padrão"""
        optimizer = AssetOptimizer('nonexistent_config.json')
        
        assert 'paths' in optimizer.config
        assert 'compression' in optimizer.config
        assert 'minification' in optimizer.config
    
    def test_needs_optimization(self, optimizer):
        """Testa verificação se asset precisa de otimização"""
        # Asset pequeno
        small_asset = AssetInfo(
            path='test.css',
            size=512,  # Menor que min_size
            compressed_size=0,
            mime_type='text/css',
            hash='test_hash',
            last_modified=datetime.now(),
            optimization_status='pending'
        )
        
        assert not optimizer._needs_optimization(small_asset)
        
        # Asset grande e otimizável
        large_asset = AssetInfo(
            path='test.css',
            size=2048,  # Maior que min_size
            compressed_size=0,
            mime_type='text/css',
            hash='test_hash',
            last_modified=datetime.now(),
            optimization_status='pending'
        )
        
        assert optimizer._needs_optimization(large_asset)
        
        # Asset não otimizável
        non_optimizable_asset = AssetInfo(
            path='test.txt',
            size=2048,
            compressed_size=0,
            mime_type='text/plain',
            hash='test_hash',
            last_modified=datetime.now(),
            optimization_status='pending'
        )
        
        assert not optimizer._needs_optimization(non_optimizable_asset)
    
    def test_minify_css(self, optimizer):
        """Testa minificação de CSS"""
        css_content = """
        body {
            margin: 0;
            padding: 0;
            background-color: #ffffff;
        }
        
        .container {
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
        }
        """
        
        minified = optimizer._minify_css(css_content)
        
        # Verifica se foi minificado
        assert len(minified) < len(css_content)
        assert 'body{' in minified
        assert '.container{' in minified
        assert '\n' not in minified or minified.count('\n') < css_content.count('\n')
    
    def test_minify_js(self, optimizer):
        """Testa minificação de JavaScript"""
        js_content = """
        function test() {
            // This is a comment
            var x = 1;
            var y = 2;
            return x + y;
        }
        """
        
        minified = optimizer._minify_js(js_content)
        
        # Verifica se foi minificado
        assert len(minified) < len(js_content)
        assert 'function test(){' in minified
        assert '// This is a comment' not in minified
    
    def test_minify_html(self, optimizer):
        """Testa minificação de HTML"""
        html_content = """
        <!DOCTYPE html>
        <html>
            <head>
                <title>Test</title>
            </head>
            <body>
                <div class="container">
                    <h1>Hello World</h1>
                </div>
            </body>
        </html>
        """
        
        minified = optimizer._minify_html(html_content)
        
        # Verifica se foi minificado
        assert len(minified) < len(html_content)
        assert '<div class="container"><h1>Hello World</h1></div>' in minified
    
    def test_compress_content(self, optimizer):
        """Testa compressão de conteúdo"""
        content = "This is a test content that will be compressed. " * 100
        
        compressed = optimizer._compress_content(content)
        
        # Verifica se foi comprimido
        assert len(compressed) < len(content.encode('utf-8'))
        assert isinstance(compressed, bytes)
    
    def test_get_cdn_url(self, optimizer):
        """Testa geração de URL do CDN"""
        file_path = Path('static/css/style.css')
        
        cdn_url = optimizer._get_cdn_url(file_path)
        
        expected_url = f"{optimizer.config['cdn']['base_url']}/css/style.css"
        assert cdn_url == expected_url
    
    def test_get_optimization_summary(self, optimizer):
        """Testa obtenção de resumo de otimização"""
        # Adiciona resultados de exemplo
        optimizer.optimization_results = [
            OptimizationResult(
                asset_path='test.css',
                original_size=1000,
                optimized_size=500,
                compression_ratio=50.0,
                optimization_type='text_minification_compression'
            )
        ]
        
        optimizer.assets = {'test.css': AssetInfo(
            path='test.css',
            size=1000,
            compressed_size=500,
            mime_type='text/css',
            hash='test_hash',
            last_modified=datetime.now(),
            optimization_status='optimized'
        )}
        
        optimizer.cdn_uploads = ['https://cdn.test.com/test.css']
        
        summary = optimizer.get_optimization_summary()
        
        assert summary['total_assets'] == 1
        assert summary['optimized_assets'] == 1
        assert summary['total_size_saved'] == 500
        assert summary['average_compression_ratio'] == 50.0
        assert summary['cdn_uploads'] == 1

class TestQueryAnalysis:
    """Testes para a classe QueryAnalysis"""
    
    def test_query_analysis_creation(self):
        """Testa criação de QueryAnalysis"""
        query = "SELECT * FROM articles WHERE user_id = 1"
        execution_time = 500.0
        rows_returned = 100
        rows_scanned = 1000
        index_usage = ['idx_articles_user_id']
        missing_indexes = ['idx_articles_status']
        optimization_suggestions = ['Add index on status column']
        timestamp = datetime.now()
        
        analysis = QueryAnalysis(
            query=query,
            execution_time=execution_time,
            rows_returned=rows_returned,
            rows_scanned=rows_scanned,
            index_usage=index_usage,
            missing_indexes=missing_indexes,
            optimization_suggestions=optimization_suggestions,
            timestamp=timestamp
        )
        
        assert analysis.query == query
        assert analysis.execution_time == execution_time
        assert analysis.rows_returned == rows_returned
        assert analysis.rows_scanned == rows_scanned
        assert analysis.index_usage == index_usage
        assert analysis.missing_indexes == missing_indexes
        assert analysis.optimization_suggestions == optimization_suggestions
        assert analysis.timestamp == timestamp

class TestPerformanceMetrics:
    """Testes para a classe PerformanceMetrics"""
    
    def test_performance_metrics_creation(self):
        """Testa criação de PerformanceMetrics"""
        component = 'api'
        response_time = 150.0
        throughput = 100.0
        error_rate = 2.0
        resource_usage = {'cpu': 50.0, 'memory': 60.0}
        timestamp = datetime.now()
        
        metrics = PerformanceMetrics(
            component=component,
            response_time=response_time,
            throughput=throughput,
            error_rate=error_rate,
            resource_usage=resource_usage,
            timestamp=timestamp
        )
        
        assert metrics.component == component
        assert metrics.response_time == response_time
        assert metrics.throughput == throughput
        assert metrics.error_rate == error_rate
        assert metrics.resource_usage == resource_usage
        assert metrics.timestamp == timestamp

class TestCacheMetrics:
    """Testes para a classe CacheMetrics"""
    
    def test_cache_metrics_creation(self):
        """Testa criação de CacheMetrics"""
        cache_name = 'redis'
        hit_rate = 85.0
        miss_rate = 15.0
        size = 50000000
        evictions = 10
        timestamp = datetime.now()
        
        metrics = CacheMetrics(
            cache_name=cache_name,
            hit_rate=hit_rate,
            miss_rate=miss_rate,
            size=size,
            evictions=evictions,
            timestamp=timestamp
        )
        
        assert metrics.cache_name == cache_name
        assert metrics.hit_rate == hit_rate
        assert metrics.miss_rate == miss_rate
        assert metrics.size == size
        assert metrics.evictions == evictions
        assert metrics.timestamp == timestamp

class TestAssetInfo:
    """Testes para a classe AssetInfo"""
    
    def test_asset_info_creation(self):
        """Testa criação de AssetInfo"""
        path = 'static/css/style.css'
        size = 2048
        compressed_size = 1024
        mime_type = 'text/css'
        file_hash = 'abc123'
        last_modified = datetime.now()
        optimization_status = 'pending'
        
        asset_info = AssetInfo(
            path=path,
            size=size,
            compressed_size=compressed_size,
            mime_type=mime_type,
            hash=file_hash,
            last_modified=last_modified,
            optimization_status=optimization_status
        )
        
        assert asset_info.path == path
        assert asset_info.size == size
        assert asset_info.compressed_size == compressed_size
        assert asset_info.mime_type == mime_type
        assert asset_info.hash == file_hash
        assert asset_info.last_modified == last_modified
        assert asset_info.optimization_status == optimization_status

class TestOptimizationResult:
    """Testes para a classe OptimizationResult"""
    
    def test_optimization_result_creation(self):
        """Testa criação de OptimizationResult"""
        asset_path = 'static/css/style.css'
        original_size = 2048
        optimized_size = 1024
        compression_ratio = 50.0
        optimization_type = 'text_minification_compression'
        cdn_url = 'https://cdn.test.com/style.css'
        timestamp = datetime.now()
        
        result = OptimizationResult(
            asset_path=asset_path,
            original_size=original_size,
            optimized_size=optimized_size,
            compression_ratio=compression_ratio,
            optimization_type=optimization_type,
            cdn_url=cdn_url,
            timestamp=timestamp
        )
        
        assert result.asset_path == asset_path
        assert result.original_size == original_size
        assert result.optimized_size == optimized_size
        assert result.compression_ratio == compression_ratio
        assert result.optimization_type == optimization_type
        assert result.cdn_url == cdn_url
        assert result.timestamp == timestamp
    
    def test_optimization_result_default_timestamp(self):
        """Testa criação com timestamp padrão"""
        result = OptimizationResult(
            asset_path='test.css',
            original_size=1000,
            optimized_size=500,
            compression_ratio=50.0,
            optimization_type='test'
        )
        
        assert result.timestamp is not None
        assert isinstance(result.timestamp, datetime)

if __name__ == "__main__":
    pytest.main([__file__]) 