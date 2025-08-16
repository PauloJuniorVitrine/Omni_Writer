/**
 * Lighthouse CI Configuration - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-027.2
 * Data/Hora: 2025-01-28T02:42:00Z
 * Tracing ID: UI_IMPLEMENTATION_FINAL_20250128_001
 * 
 * Funcionalidades:
 * - Configuração do Lighthouse CI
 * - Thresholds de performance
 * - Integração com CI/CD
 * - Relatórios automáticos
 */

module.exports = {
  ci: {
    collect: {
      // Configurações de coleta
      url: [
        'http://localhost:3000',
        'http://localhost:3000/dashboard',
        'http://localhost:3000/article-generation',
        'http://localhost:3000/blogs',
        'http://localhost:3000/categories',
        'http://localhost:3000/prompts',
        'http://localhost:3000/monitoring',
        'http://localhost:3000/security',
        'http://localhost:3000/pipeline'
      ],
      numberOfRuns: 3,
      startServerCommand: 'npm run start',
      startServerReadyPattern: 'Local:.+http://localhost:3000',
      startServerReadyTimeout: 30000,
      chromePath: process.env.CHROME_PATH,
      puppeteerScript: './scripts/lighthouse-puppeteer.js',
      puppeteerLaunchOptions: {
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--no-first-run',
          '--no-zygote',
          '--disable-gpu'
        ]
      },
      settings: {
        chromeFlags: '--disable-gpu --no-sandbox --disable-dev-shm-usage',
        onlyCategories: ['performance', 'accessibility', 'best-practices', 'seo'],
        formFactor: 'desktop',
        throttling: {
          rttMs: 40,
          throughputKbps: 10240,
          cpuSlowdownMultiplier: 1,
          requestLatencyMs: 0,
          downloadThroughputKbps: 0,
          uploadThroughputKbps: 0
        },
        screenEmulation: {
          mobile: false,
          width: 1350,
          height: 940,
          deviceScaleFactor: 1,
          disabled: false
        },
        emulatedUserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      }
    },
    
    assert: {
      // Assertions e thresholds
      assertions: {
        // Performance
        'categories:performance': ['error', { minScore: 0.90 }],
        'first-contentful-paint': ['error', { maxNumericValue: 2000 }],
        'largest-contentful-paint': ['error', { maxNumericValue: 2500 }],
        'cumulative-layout-shift': ['error', { maxNumericValue: 0.1 }],
        'total-blocking-time': ['error', { maxNumericValue: 300 }],
        'speed-index': ['error', { maxNumericValue: 3000 }],
        
        // Accessibility
        'categories:accessibility': ['error', { minScore: 0.95 }],
        'color-contrast': 'off',
        'image-alt': 'off',
        
        // Best Practices
        'categories:best-practices': ['error', { minScore: 0.90 }],
        'uses-https': 'off',
        'external-anchors-use-rel-noopener': 'off',
        
        // SEO
        'categories:seo': ['error', { minScore: 0.90 }],
        'robots-txt': 'off',
        'structured-data': 'off',
        
        // Core Web Vitals
        'core-web-vitals': ['error', { minScore: 0.90 }],
        
        // Bundle Analysis
        'unused-javascript': ['warn', { maxLength: 100 }],
        'unused-css-rules': ['warn', { maxLength: 50 }],
        'modern-image-formats': 'off',
        'uses-optimized-images': 'off',
        'uses-text-compression': 'off',
        'uses-responsive-images': 'off',
        'efficient-animated-content': 'off',
        'preload-lcp-image': 'off',
        'uses-rel-preload': 'off',
        'uses-rel-preconnect': 'off',
        'font-display': 'off',
        'unminified-css': 'off',
        'unminified-javascript': 'off',
        'unused-css-rules': 'off',
        'unused-javascript': 'off',
        'uses-long-cache-ttl': 'off',
        'dom-size': 'off',
        'critical-request-chains': 'off',
        'user-timings': 'off',
        'bootup-time': 'off',
        'mainthread-work-breakdown': 'off',
        'font-display': 'off',
        'resource-summary': 'off',
        'third-party-summary': 'off',
        'largest-contentful-paint-element': 'off',
        'layout-shift-elements': 'off',
        'long-tasks': 'off',
        'non-composited-animations': 'off',
        'unsized-images': 'off'
      }
    },
    
    upload: {
      // Upload de resultados
      target: 'temporary-public-storage',
      githubToken: process.env.GITHUB_TOKEN,
      githubAppToken: process.env.GITHUB_APP_TOKEN,
      githubStatusContextSuffix: 'Lighthouse',
      githubChecksContext: 'Lighthouse',
      githubChecksAppId: process.env.GITHUB_APP_ID,
      githubChecksAppKey: process.env.GITHUB_APP_KEY,
      githubChecksInstallationId: process.env.GITHUB_INSTALLATION_ID,
      githubChecksRepoOwner: process.env.GITHUB_REPO_OWNER,
      githubChecksRepoName: process.env.GITHUB_REPO_NAME,
      githubChecksCommitSha: process.env.GITHUB_SHA,
      githubChecksBranch: process.env.GITHUB_REF,
      githubChecksPullRequestNumber: process.env.GITHUB_PR_NUMBER
    }
  },
  
  // Configurações específicas por ambiente
  environments: {
    development: {
      ci: {
        collect: {
          url: ['http://localhost:3000'],
          numberOfRuns: 1
        },
        assert: {
          assertions: {
            'categories:performance': ['warn', { minScore: 0.70 }],
            'categories:accessibility': ['warn', { minScore: 0.80 }],
            'categories:best-practices': ['warn', { minScore: 0.70 }],
            'categories:seo': ['warn', { minScore: 0.70 }]
          }
        }
      }
    },
    
    staging: {
      ci: {
        collect: {
          url: [
            'https://staging.omniwriter.com',
            'https://staging.omniwriter.com/dashboard',
            'https://staging.omniwriter.com/article-generation'
          ],
          numberOfRuns: 2
        },
        assert: {
          assertions: {
            'categories:performance': ['error', { minScore: 0.85 }],
            'categories:accessibility': ['error', { minScore: 0.90 }],
            'categories:best-practices': ['error', { minScore: 0.85 }],
            'categories:seo': ['error', { minScore: 0.85 }]
          }
        }
      }
    },
    
    production: {
      ci: {
        collect: {
          url: [
            'https://omniwriter.com',
            'https://omniwriter.com/dashboard',
            'https://omniwriter.com/article-generation',
            'https://omniwriter.com/blogs',
            'https://omniwriter.com/categories',
            'https://omniwriter.com/prompts',
            'https://omniwriter.com/monitoring',
            'https://omniwriter.com/security',
            'https://omniwriter.com/pipeline'
          ],
          numberOfRuns: 3
        },
        assert: {
          assertions: {
            'categories:performance': ['error', { minScore: 0.90 }],
            'categories:accessibility': ['error', { minScore: 0.95 }],
            'categories:best-practices': ['error', { minScore: 0.90 }],
            'categories:seo': ['error', { minScore: 0.90 }],
            'first-contentful-paint': ['error', { maxNumericValue: 1500 }],
            'largest-contentful-paint': ['error', { maxNumericValue: 2000 }],
            'cumulative-layout-shift': ['error', { maxNumericValue: 0.1 }],
            'total-blocking-time': ['error', { maxNumericValue: 200 }],
            'speed-index': ['error', { maxNumericValue: 2000 }]
          }
        }
      }
    }
  },
  
  // Configurações de relatórios
  reports: {
    formats: ['html', 'json', 'csv'],
    directory: './lighthouse-reports',
    fileName: 'lighthouse-report-{date}-{time}'
  },
  
  // Configurações de notificações
  notifications: {
    slack: {
      webhookUrl: process.env.SLACK_WEBHOOK_URL,
      channel: '#lighthouse-reports',
      username: 'Lighthouse Bot',
      iconEmoji: ':lighthouse:'
    },
    
    email: {
      smtp: {
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: true,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      },
      from: 'lighthouse@omniwriter.com',
      to: ['dev-team@omniwriter.com'],
      subject: 'Lighthouse Report - {date}'
    }
  },
  
  // Configurações de cache
  cache: {
    directory: './.lighthouse-cache',
    maxAge: 24 * 60 * 60 * 1000 // 24 horas
  },
  
  // Configurações de debug
  debug: {
    enabled: process.env.NODE_ENV === 'development',
    level: 'info',
    logFile: './lighthouse-debug.log'
  }
}; 