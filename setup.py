from setuptools import setup, find_packages

setup(
    name='omni_gerador_artigos',
    version='1.0.0',
    description='Omni Gerador de Artigos em Massa via IA',
    author='Omni Writer Team',
    author_email='team@omniwriter.com',
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.10',
    install_requires=[
        # Core Frameworks
        'Flask==3.1.0',
        'Flask-WTF>=1.1.1',
        'Flask-Limiter>=3.5.0',
        'Flask-RESTX==1.3.0',
        'Werkzeug==3.1.3',
        'Jinja2==3.1.6',
        
        # Database
        'SQLAlchemy>=2.0.0',
        'sqlmodel==0.0.24',
        'alembic>=1.12.0',
        'psycopg2-binary>=2.9.0',
        'redis>=4.0.0',
        
        # Async Tasks
        'celery[redis]>=5.3.6',
        'APScheduler==3.10.4',
        
        # HTTP and APIs
        'requests==2.32.3',
        'httpx==0.28.1',
        'openai==1.76.0',
        'stripe>=7.0.0',
        
        # Validation
        'pydantic==2.11.3',
        'pydantic_core==2.33.1',
        'email-validator>=2.0.0',
        'python-multipart>=0.0.6',
        
        # Security
        'cryptography==44.0.2',
        'bcrypt==4.3.0',
        'passlib==1.7.4',
        'python-jose==3.4.0',
        'python-magic==0.4.27',
        'bleach==6.1.0',
        
        # Monitoring
        'prometheus-client>=0.17.0',
        'prometheus-flask-exporter>=0.22.4',
        'structlog>=23.1.0',
        'python-json-logger>=2.0.7',
        'psutil>=5.9.0',
        
        # Machine Learning
        'scikit-learn==1.6.1',
        'numpy==2.2.5',
        'pandas==2.2.3',
        'sentence-transformers>=2.2.2',
        'nltk>=3.8.1',
        
        # Utils
        'python-dotenv==1.1.0',
        'PyYAML==6.0.2',
        'tqdm==4.67.1',
        'colorama==0.4.6',
    ],
    extras_require={
        'dev': [
            'black>=23.0.0',
            'flake8>=6.0.0',
            'isort>=5.12.0',
            'mypy>=1.5.0',
            'pylint>=2.17.0',
            'sphinx>=7.0.0',
            'sphinx-rtd-theme>=1.3.0',
            'ipdb>=0.13.0',
            'ipython>=8.0.0',
            'pre-commit>=3.3.0',
            'tox>=4.6.0',
        ],
        'test': [
            'pytest==7.4.0',
            'pytest-asyncio==0.21.1',
            'pytest-cov==4.1.0',
            'pytest-mock==3.11.1',
            'pytest-xdist>=3.0.0',
            'locust>=2.15.0',
            'selenium>=4.0.0',
            'webdriver-manager>=3.8.0',
            'percy>=2.0.0',
            'mutmut==2.4.4',
            'bandit>=1.7.0',
            'safety>=2.3.0',
            'coverage>=7.3.0',
        ],
        'prod': [
            'gunicorn>=21.0.0',
            'gevent>=23.0.0',
            'memcached>=1.0.0',
            'loguru>=0.7.0',
        ],
        'ml': [
            'scikit-learn==1.6.1',
            'numpy==2.2.5',
            'pandas==2.2.3',
            'scipy==1.15.2',
            'sentence-transformers>=2.2.2',
            'nltk>=3.8.1',
            'matplotlib==3.10.1',
            'pillow==11.2.1',
            'seaborn>=0.12.0',
            'plotly>=5.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'omni-gerador=app.main:main',
            'omni-worker=app.celery_worker:main',
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Text Processing :: Linguistic',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
    ],
    keywords='ai, nlp, content-generation, machine-learning, flask, python',
    project_urls={
        'Bug Reports': 'https://github.com/omniwriter/omniwriter/issues',
        'Source': 'https://github.com/omniwriter/omniwriter',
        'Documentation': 'https://docs.omniwriter.com',
    },
) 