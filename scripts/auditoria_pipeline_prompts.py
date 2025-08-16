import os
import ast

PROJ_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
IGNORED_DIRS = {'venv', '__pycache__', 'site-packages', 'dist', 'build', 'node_modules'}

class PromptsAuditVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.suspects = []

    def visit_Call(self, node):
        # Busca chamadas a run_generation_pipeline
        if isinstance(node.func, ast.Name) and node.func.id == 'run_generation_pipeline':
            if node.args:
                arg = node.args[0]
                if not (isinstance(arg, ast.Name) and arg.id.lower().startswith('config')):
                    self.suspects.append((node.lineno, 'Chamada suspeita a run_generation_pipeline', ast.unparse(node)))
        self.generic_visit(node)

    def visit_Attribute(self, node):
        # Busca acessos a .prompts
        if node.attr == 'prompts':
            self.suspects.append((node.lineno, 'Acesso a .prompts', ast.unparse(node)))
        self.generic_visit(node)

def audit_project():
    print('--- Auditoria de uso de run_generation_pipeline e .prompts ---')
    for root, dirs, files in os.walk(PROJ_ROOT):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        source = f.read()
                    tree = ast.parse(source, filename=path)
                    visitor = PromptsAuditVisitor(path)
                    visitor.visit(tree)
                    for lineno, msg, code in visitor.suspects:
                        print(f'{path}:{lineno}: {msg}\n    {code}\n')
                except Exception as e:
                    print(f'Erro ao analisar {path}: {e}')
    print('--- Fim da auditoria ---')

if __name__ == '__main__':
    audit_project() 