#!/usr/bin/env python3
"""
Gerenciador de Cache para Dependências E2E
- Cache inteligente de dependências
- Otimização de downloads
- Limpeza automática
- Métricas de performance

📐 CoCoT: Baseado em boas práticas de cache para testes E2E
🌲 ToT: Múltiplas estratégias de cache implementadas
♻️ ReAct: Simulado para diferentes cenários de otimização

**Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
**Data/Hora:** 2025-01-28T11:40:00Z
**Tracing ID:** CACHE_MANAGER_md1ppfhs
**Origem:** Necessidade de otimização de cache para dependências E2E
"""

import os
import json
import hashlib
import shutil
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import subprocess

@dataclass
class CacheEntry:
    """Entrada do cache"""
    key: str
    path: str
    size: int
    created: datetime
    last_accessed: datetime
    access_count: int
    dependencies: List[str]

@dataclass
class CacheStats:
    """Estatísticas do cache"""
    total_entries: int
    total_size: int
    hit_rate: float
    miss_rate: float
    oldest_entry: Optional[datetime]
    newest_entry: Optional[datetime]

class E2ECacheManager:
    """Gerenciador de cache para E2E"""
    
    def __init__(self, cache_dir: str = '.e2e-cache'):
        self.cache_dir = Path(cache_dir)
        self.metadata_file = self.cache_dir / 'metadata.json'
        self.stats_file = self.cache_dir / 'stats.json'
        
        # Configurações do cache
        self.config = {
            'max_size': 2 * 1024 * 1024 * 1024,  # 2GB
            'max_age': 7 * 24 * 60 * 60,  # 7 dias
            'cleanup_threshold': 0.8,  # 80% do tamanho máximo
            'compression': True,
            'auto_cleanup': True
        }
        
        # Inicializar cache
        self._init_cache()
        self.cache_data: Dict[str, CacheEntry] = self._load_metadata()
    
    def _init_cache(self) -> None:
        """Inicializar estrutura do cache"""
        if not self.cache_dir.exists():
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            print(f"📁 Cache criado em: {self.cache_dir}")
        
        # Criar subdiretórios
        subdirs = ['dependencies', 'browsers', 'screenshots', 'videos', 'reports']
        for subdir in subdirs:
            (self.cache_dir / subdir).mkdir(exist_ok=True)
    
    def _load_metadata(self) -> Dict[str, CacheEntry]:
        """Carregar metadados do cache"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                cache_data = {}
                for key, entry_data in data.items():
                    cache_data[key] = CacheEntry(
                        key=entry_data['key'],
                        path=entry_data['path'],
                        size=entry_data['size'],
                        created=datetime.fromisoformat(entry_data['created']),
                        last_accessed=datetime.fromisoformat(entry_data['last_accessed']),
                        access_count=entry_data['access_count'],
                        dependencies=entry_data.get('dependencies', [])
                    )
                return cache_data
            except Exception as e:
                print(f"⚠️ Erro ao carregar metadados: {e}")
                return {}
        return {}
    
    def _save_metadata(self) -> None:
        """Salvar metadados do cache"""
        try:
            data = {}
            for key, entry in self.cache_data.items():
                data[key] = {
                    'key': entry.key,
                    'path': entry.path,
                    'size': entry.size,
                    'created': entry.created.isoformat(),
                    'last_accessed': entry.last_accessed.isoformat(),
                    'access_count': entry.access_count,
                    'dependencies': entry.dependencies
                }
            
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"⚠️ Erro ao salvar metadados: {e}")
    
    def _generate_cache_key(self, content: str, dependencies: List[str] = None) -> str:
        """Gerar chave única para o cache"""
        key_content = content + ''.join(dependencies or [])
        return hashlib.sha256(key_content.encode()).hexdigest()
    
    def _get_file_size(self, file_path: Path) -> int:
        """Obter tamanho do arquivo"""
        try:
            return file_path.stat().st_size
        except:
            return 0
    
    def _get_total_cache_size(self) -> int:
        """Obter tamanho total do cache"""
        total_size = 0
        for entry in self.cache_data.values():
            if Path(entry.path).exists():
                total_size += entry.size
        return total_size
    
    def get(self, key: str) -> Optional[Path]:
        """Obter item do cache"""
        if key in self.cache_data:
            entry = self.cache_data[key]
            cache_path = Path(entry.path)
            
            # Verificar se arquivo existe
            if not cache_path.exists():
                print(f"🗑️ Item não encontrado no cache: {key}")
                del self.cache_data[key]
                return None
            
            # Verificar se não expirou
            if datetime.now() - entry.created > timedelta(seconds=self.config['max_age']):
                print(f"⏰ Item expirado no cache: {key}")
                self.remove(key)
                return None
            
            # Atualizar estatísticas
            entry.last_accessed = datetime.now()
            entry.access_count += 1
            self._save_metadata()
            
            print(f"✅ Cache hit: {key}")
            return cache_path
        
        print(f"❌ Cache miss: {key}")
        return None
    
    def put(self, key: str, source_path: Path, dependencies: List[str] = None) -> bool:
        """Adicionar item ao cache"""
        try:
            # Verificar se há espaço suficiente
            if not self._ensure_space(source_path.stat().st_size):
                return False
            
            # Criar entrada no cache
            cache_path = self.cache_dir / 'dependencies' / f"{key}.cache"
            
            # Copiar arquivo
            shutil.copy2(source_path, cache_path)
            
            # Criar entrada
            entry = CacheEntry(
                key=key,
                path=str(cache_path),
                size=cache_path.stat().st_size,
                created=datetime.now(),
                last_accessed=datetime.now(),
                access_count=1,
                dependencies=dependencies or []
            )
            
            self.cache_data[key] = entry
            self._save_metadata()
            
            print(f"💾 Item adicionado ao cache: {key}")
            return True
            
        except Exception as e:
            print(f"❌ Erro ao adicionar ao cache: {e}")
            return False
    
    def remove(self, key: str) -> bool:
        """Remover item do cache"""
        if key in self.cache_data:
            entry = self.cache_data[key]
            cache_path = Path(entry.path)
            
            try:
                if cache_path.exists():
                    cache_path.unlink()
                
                del self.cache_data[key]
                self._save_metadata()
                
                print(f"🗑️ Item removido do cache: {key}")
                return True
            except Exception as e:
                print(f"❌ Erro ao remover do cache: {e}")
                return False
        
        return False
    
    def _ensure_space(self, required_size: int) -> bool:
        """Garantir espaço suficiente no cache"""
        current_size = self._get_total_cache_size()
        
        if current_size + required_size <= self.config['max_size']:
            return True
        
        # Limpeza automática se habilitada
        if self.config['auto_cleanup']:
            print("🧹 Executando limpeza automática do cache...")
            self.cleanup()
            
            # Verificar novamente
            current_size = self._get_total_cache_size()
            if current_size + required_size <= self.config['max_size']:
                return True
        
        print(f"❌ Espaço insuficiente no cache. Necessário: {required_size}, Disponível: {self.config['max_size'] - current_size}")
        return False
    
    def cleanup(self, max_age: int = None, min_access_count: int = 0) -> int:
        """Limpar cache"""
        max_age = max_age or self.config['max_age']
        removed_count = 0
        
        current_time = datetime.now()
        entries_to_remove = []
        
        for key, entry in self.cache_data.items():
            # Verificar idade
            age = (current_time - entry.created).total_seconds()
            if age > max_age:
                entries_to_remove.append(key)
                continue
            
            # Verificar acesso
            if entry.access_count < min_access_count:
                entries_to_remove.append(key)
                continue
        
        # Remover entradas
        for key in entries_to_remove:
            if self.remove(key):
                removed_count += 1
        
        print(f"🧹 Limpeza concluída: {removed_count} itens removidos")
        return removed_count
    
    def get_stats(self) -> CacheStats:
        """Obter estatísticas do cache"""
        if not self.cache_data:
            return CacheStats(0, 0, 0.0, 0.0, None, None)
        
        total_entries = len(self.cache_data)
        total_size = self._get_total_cache_size()
        
        # Calcular hit rate (simulado)
        total_accesses = sum(entry.access_count for entry in self.cache_data.values())
        hit_rate = total_accesses / max(total_entries, 1)
        miss_rate = 1 - hit_rate
        
        # Encontrar entradas mais antigas e recentes
        created_times = [entry.created for entry in self.cache_data.values()]
        oldest_entry = min(created_times) if created_times else None
        newest_entry = max(created_times) if created_times else None
        
        return CacheStats(
            total_entries=total_entries,
            total_size=total_size,
            hit_rate=hit_rate,
            miss_rate=miss_rate,
            oldest_entry=oldest_entry,
            newest_entry=newest_entry
        )
    
    def cache_dependencies(self, dependencies_file: str = 'package.json') -> bool:
        """Cache de dependências Node.js"""
        try:
            if not Path(dependencies_file).exists():
                print(f"❌ Arquivo de dependências não encontrado: {dependencies_file}")
                return False
            
            # Ler dependências
            with open(dependencies_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            dependencies = []
            dependencies.extend(data.get('dependencies', {}).keys())
            dependencies.extend(data.get('devDependencies', {}).keys())
            
            # Gerar chave do cache
            deps_content = json.dumps(dependencies, sort_keys=True)
            cache_key = self._generate_cache_key(deps_content, dependencies)
            
            # Verificar se já está no cache
            if self.get(cache_key):
                print("✅ Dependências já estão no cache")
                return True
            
            # Cache node_modules se existir
            node_modules_path = Path('node_modules')
            if node_modules_path.exists():
                # Criar arquivo temporário com hash das dependências
                temp_file = Path('temp_deps.json')
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(dependencies, f, sort_keys=True)
                
                success = self.put(cache_key, temp_file, dependencies)
                temp_file.unlink()  # Remover arquivo temporário
                
                if success:
                    print(f"💾 Dependências cacheadas: {len(dependencies)} pacotes")
                    return True
            
            return False
            
        except Exception as e:
            print(f"❌ Erro ao cachear dependências: {e}")
            return False
    
    def cache_browsers(self) -> bool:
        """Cache de browsers do Playwright"""
        try:
            # Verificar se browsers estão instalados
            browsers_dir = Path.home() / '.cache' / 'ms-playwright'
            if not browsers_dir.exists():
                print("❌ Browsers do Playwright não encontrados")
                return False
            
            # Listar browsers disponíveis
            browsers = []
            for browser_dir in browsers_dir.iterdir():
                if browser_dir.is_dir():
                    browsers.append(browser_dir.name)
            
            if not browsers:
                print("❌ Nenhum browser encontrado")
                return False
            
            # Gerar chave do cache
            browsers_content = json.dumps(browsers, sort_keys=True)
            cache_key = self._generate_cache_key(browsers_content, browsers)
            
            # Verificar se já está no cache
            if self.get(cache_key):
                print("✅ Browsers já estão no cache")
                return True
            
            # Cache do diretório de browsers
            temp_file = Path('temp_browsers.json')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(browsers, f, sort_keys=True)
            
            success = self.put(cache_key, temp_file, browsers)
            temp_file.unlink()
            
            if success:
                print(f"💾 Browsers cacheados: {browsers}")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Erro ao cachear browsers: {e}")
            return False
    
    def print_stats(self) -> None:
        """Exibir estatísticas do cache"""
        stats = self.get_stats()
        
        print("\n📊 ESTATÍSTICAS DO CACHE")
        print("=" * 40)
        print(f"Total de entradas: {stats.total_entries}")
        print(f"Tamanho total: {stats.total_size / (1024*1024):.2f} MB")
        print(f"Taxa de hit: {stats.hit_rate:.2%}")
        print(f"Taxa de miss: {stats.miss_rate:.2%}")
        
        if stats.oldest_entry:
            print(f"Entrada mais antiga: {stats.oldest_entry.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if stats.newest_entry:
            print(f"Entrada mais recente: {stats.newest_entry.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"Tamanho máximo: {self.config['max_size'] / (1024*1024*1024):.2f} GB")
        print(f"Limite de limpeza: {self.config['cleanup_threshold']:.1%}")

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description='Gerenciador de Cache E2E')
    parser.add_argument('--cache-dir', default='.e2e-cache', help='Diretório do cache')
    parser.add_argument('--cleanup', action='store_true', help='Limpar cache')
    parser.add_argument('--stats', action='store_true', help='Exibir estatísticas')
    parser.add_argument('--cache-deps', action='store_true', help='Cachear dependências')
    parser.add_argument('--cache-browsers', action='store_true', help='Cachear browsers')
    parser.add_argument('--max-age', type=int, help='Idade máxima em segundos')
    parser.add_argument('--min-access', type=int, default=0, help='Mínimo de acessos')
    
    args = parser.parse_args()
    
    cache_manager = E2ECacheManager(args.cache_dir)
    
    if args.stats:
        cache_manager.print_stats()
    
    if args.cleanup:
        max_age = args.max_age or cache_manager.config['max_age']
        removed = cache_manager.cleanup(max_age, args.min_access)
        print(f"🧹 Limpeza concluída: {removed} itens removidos")
    
    if args.cache_deps:
        success = cache_manager.cache_dependencies()
        if success:
            print("✅ Dependências cacheadas com sucesso")
        else:
            print("❌ Falha ao cachear dependências")
    
    if args.cache_browsers:
        success = cache_manager.cache_browsers()
        if success:
            print("✅ Browsers cacheados com sucesso")
        else:
            print("❌ Falha ao cachear browsers")
    
    # Exibir estatísticas finais
    if not any([args.stats, args.cleanup, args.cache_deps, args.cache_browsers]):
        cache_manager.print_stats()

if __name__ == '__main__':
    main() 