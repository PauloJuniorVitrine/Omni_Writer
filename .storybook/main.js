/**
 * Storybook Main Configuration - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-026.1
 * Data/Hora: 2025-01-28T02:39:00Z
 * Tracing ID: UI_IMPLEMENTATION_FINAL_20250128_001
 * 
 * Funcionalidades:
 * - Configuração principal do Storybook
 * - Addons essenciais
 * - Addon de acessibilidade
 * - Addon de performance
 * - Configuração de TypeScript
 */

module.exports = {
  stories: [
    '../ui/stories/**/*.stories.@(js|jsx|ts|tsx|mdx)',
    '../ui/components/**/*.stories.@(js|jsx|ts|tsx|mdx)',
    '../ui/pages/**/*.stories.@(js|jsx|ts|tsx|mdx)'
  ],
  
  addons: [
    '@storybook/addon-links',
    '@storybook/addon-essentials',
    '@storybook/addon-interactions',
    '@storybook/addon-a11y',
    '@storybook/addon-performance',
    '@storybook/addon-viewport',
    '@storybook/addon-backgrounds',
    '@storybook/addon-measure',
    '@storybook/addon-outline',
    '@storybook/addon-docs',
    '@storybook/addon-controls',
    '@storybook/addon-actions',
    '@storybook/addon-toolbars',
    '@storybook/addon-coverage',
    '@storybook/addon-jest',
    '@storybook/addon-storysource',
    '@storybook/addon-knobs',
    '@storybook/addon-notes',
    '@storybook/addon-info',
    '@storybook/addon-contexts',
    '@storybook/addon-queryparams',
    '@storybook/addon-graphql',
    '@storybook/addon-cssresources',
    '@storybook/addon-grid',
    '@storybook/addon-paddings',
    '@storybook/addon-themes',
    '@storybook/addon-designs',
    '@storybook/addon-docs-toc',
    '@storybook/addon-docs-blocks',
    '@storybook/addon-storyshots',
    '@storybook/addon-storyshots-puppeteer',
    '@storybook/addon-storysource',
    '@storybook/addon-storybook-design-token',
    '@storybook/addon-storybook-react-docgen-typescript-plugin'
  ],
  
  framework: {
    name: '@storybook/react-webpack5',
    options: {
      builder: {
        useSWC: true
      }
    }
  },
  
  typescript: {
    check: false,
    checkOptions: {},
    reactDocgen: 'react-docgen-typescript',
    reactDocgenTypescriptOptions: {
      shouldExtractLiteralValuesFromEnum: true,
      propFilter: (prop) => (prop.parent ? !/node_modules/.test(prop.parent.fileName) : true),
      compilerOptions: {
        allowSyntheticDefaultImports: false,
        esModuleInterop: false
      }
    }
  },
  
  docs: {
    autodocs: true,
    defaultName: 'Documentation'
  },
  
  core: {
    builder: '@storybook/builder-webpack5',
    disableTelemetry: true
  },
  
  features: {
    storyStoreV7: true,
    buildStoriesJson: true,
    breakingChangesV7: true,
    legacyMdx1Imports: false,
    modernInlineRender: true,
    legacyDecoratorFileStructure: false,
    storyStoreV7MdxErrors: true,
    interactionsDebugger: true,
    breakingChangesV7: true,
    storyStoreV7MdxErrors: true,
    modernInlineRender: true,
    legacyDecoratorFileStructure: false,
    storyStoreV7: true,
    buildStoriesJson: true,
    breakingChangesV7: true,
    legacyMdx1Imports: false,
    modernInlineRender: true,
    legacyDecoratorFileStructure: false,
    storyStoreV7MdxErrors: true,
    interactionsDebugger: true,
    breakingChangesV7: true,
    storyStoreV7MdxErrors: true,
    modernInlineRender: true,
    legacyDecoratorFileStructure: false
  },
  
  staticDirs: [
    '../ui/assets',
    '../ui/public'
  ],
  
  webpackFinal: async (config) => {
    // Resolve aliases
    config.resolve.alias = {
      ...config.resolve.alias,
      '@': require('path').resolve(__dirname, '../ui'),
      '@components': require('path').resolve(__dirname, '../ui/components'),
      '@pages': require('path').resolve(__dirname, '../ui/pages'),
      '@hooks': require('path').resolve(__dirname, '../ui/hooks'),
      '@utils': require('path').resolve(__dirname, '../ui/utils'),
      '@types': require('path').resolve(__dirname, '../ui/types'),
      '@assets': require('path').resolve(__dirname, '../ui/assets'),
      '@styles': require('path').resolve(__dirname, '../ui/styles')
    };
    
    // CSS/SCSS support
    config.module.rules.push({
      test: /\.css$/,
      use: [
        'style-loader',
        {
          loader: 'css-loader',
          options: {
            modules: {
              auto: true,
              localIdentName: '[name]__[local]--[hash:base64:5]'
            }
          }
        },
        'postcss-loader'
      ]
    });
    
    config.module.rules.push({
      test: /\.scss$/,
      use: [
        'style-loader',
        {
          loader: 'css-loader',
          options: {
            modules: {
              auto: true,
              localIdentName: '[name]__[local]--[hash:base64:5]'
            }
          }
        },
        'postcss-loader',
        'sass-loader'
      ]
    });
    
    // Asset support
    config.module.rules.push({
      test: /\.(png|jpg|jpeg|gif|svg)$/,
      type: 'asset/resource'
    });
    
    config.module.rules.push({
      test: /\.(woff|woff2|eot|ttf|otf)$/,
      type: 'asset/resource'
    });
    
    return config;
  },
  
  managerWebpack: async (config) => {
    // Customize manager webpack config
    return config;
  },
  
  previewWebpack: async (config) => {
    // Customize preview webpack config
    return config;
  },
  
  env: (config) => ({
    ...config,
    STORYBOOK_ENV: 'development'
  }),
  
  logLevel: 'info',
  
  previewHead: (entries) => [
    ...entries,
    '<link rel="icon" type="image/x-icon" href="/favicon.ico">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="description" content="Omni Writer - Interface Gráfica Enterprise">'
  ],
  
  previewBody: (entries) => [
    ...entries,
    '<div id="storybook-root"></div>'
  ],
  
  managerHead: (entries) => [
    ...entries,
    '<link rel="icon" type="image/x-icon" href="/favicon.ico">',
    '<title>Omni Writer - Storybook</title>'
  ]
}; 