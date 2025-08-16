/**
 * Webpack Configuration - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-025.2
 * Data/Hora: 2025-01-28T02:38:00Z
 * Tracing ID: UI_IMPLEMENTATION_FINAL_20250128_001
 * 
 * Funcionalidades:
 * - Code splitting por rota
 * - Dynamic imports otimizados
 * - Bundle size optimization
 * - Performance monitoring
 * - Development e production configs
 */

const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const TerserPlugin = require('terser-webpack-plugin');
const CssMinimizerPlugin = require('css-minimizer-webpack-plugin');
const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');

// ===== CONFIGURAÇÕES =====

const isProduction = process.env.NODE_ENV === 'production';
const isAnalyze = process.env.ANALYZE === 'true';

// ===== ENTRY POINTS =====

const entryPoints = {
  main: './ui/index.tsx',
  // Code splitting por rota
  dashboard: './ui/pages/Dashboard.tsx',
  articleGeneration: './ui/pages/ArticleGeneration.tsx',
  blogs: './ui/pages/Blogs.tsx',
  categories: './ui/pages/Categorias.tsx',
  prompts: './ui/pages/Prompts.tsx',
  monitoring: './ui/pages/Monitoring.tsx',
  security: './ui/pages/Security.tsx',
  pipeline: './ui/pages/Pipeline.tsx'
};

// ===== RESOLVE CONFIG =====

const resolveConfig = {
  extensions: ['.tsx', '.ts', '.js', '.jsx', '.json'],
  alias: {
    '@': path.resolve(__dirname, 'ui'),
    '@components': path.resolve(__dirname, 'ui/components'),
    '@pages': path.resolve(__dirname, 'ui/pages'),
    '@hooks': path.resolve(__dirname, 'ui/hooks'),
    '@utils': path.resolve(__dirname, 'ui/utils'),
    '@types': path.resolve(__dirname, 'ui/types'),
    '@assets': path.resolve(__dirname, 'ui/assets'),
    '@styles': path.resolve(__dirname, 'ui/styles')
  }
};

// ===== LOADERS =====

const loaders = [
  // TypeScript loader
  {
    test: /\.(ts|tsx)$/,
    exclude: /node_modules/,
    use: {
      loader: 'ts-loader',
      options: {
        transpileOnly: !isProduction,
        configFile: path.resolve(__dirname, 'tsconfig.json')
      }
    }
  },
  
  // CSS loader
  {
    test: /\.css$/,
    use: [
      isProduction ? MiniCssExtractPlugin.loader : 'style-loader',
      {
        loader: 'css-loader',
        options: {
          modules: {
            auto: true,
            localIdentName: isProduction ? '[hash:base64:8]' : '[name]__[local]--[hash:base64:5]'
          },
          sourceMap: !isProduction
        }
      },
      'postcss-loader'
    ]
  },
  
  // SCSS loader
  {
    test: /\.scss$/,
    use: [
      isProduction ? MiniCssExtractPlugin.loader : 'style-loader',
      {
        loader: 'css-loader',
        options: {
          modules: {
            auto: true,
            localIdentName: isProduction ? '[hash:base64:8]' : '[name]__[local]--[hash:base64:5]'
          },
          sourceMap: !isProduction
        }
      },
      'postcss-loader',
      {
        loader: 'sass-loader',
        options: {
          sourceMap: !isProduction
        }
      }
    ]
  },
  
  // Asset loaders
  {
    test: /\.(png|jpg|jpeg|gif|svg)$/,
    type: 'asset',
    parser: {
      dataUrlCondition: {
        maxSize: 8 * 1024 // 8kb
      }
    }
  },
  
  {
    test: /\.(woff|woff2|eot|ttf|otf)$/,
    type: 'asset/resource'
  }
];

// ===== PLUGINS =====

const plugins = [
  new HtmlWebpackPlugin({
    template: './ui/index.html',
    filename: 'index.html',
    chunks: ['main'],
    minify: isProduction ? {
      removeComments: true,
      collapseWhitespace: true,
      removeRedundantAttributes: true,
      useShortDoctype: true,
      removeEmptyAttributes: true,
      removeStyleLinkTypeAttributes: true,
      keepClosingSlash: true,
      minifyJS: true,
      minifyCSS: true,
      minifyURLs: true
    } : false
  }),
  
  // CSS extraction para produção
  ...(isProduction ? [
    new MiniCssExtractPlugin({
      filename: 'css/[name].[contenthash:8].css',
      chunkFilename: 'css/[name].[contenthash:8].chunk.css'
    })
  ] : []),
  
  // Bundle analyzer
  ...(isAnalyze ? [
    new BundleAnalyzerPlugin({
      analyzerMode: 'static',
      openAnalyzer: false,
      reportFilename: 'bundle-analysis.html'
    })
  ] : [])
];

// ===== OPTIMIZATION =====

const optimization = {
  minimize: isProduction,
  minimizer: [
    new TerserPlugin({
      terserOptions: {
        compress: {
          drop_console: isProduction,
          drop_debugger: isProduction
        },
        mangle: {
          safari10: true
        }
      },
      extractComments: false
    }),
    new CssMinimizerPlugin()
  ],
  
  // Code splitting
  splitChunks: {
    chunks: 'all',
    maxInitialRequests: 25,
    minSize: 20000,
    cacheGroups: {
      // Vendor chunks
      vendor: {
        test: /[\\/]node_modules[\\/]/,
        name: 'vendors',
        chunks: 'all',
        priority: 10
      },
      
      // React chunks
      react: {
        test: /[\\/]node_modules[\\/](react|react-dom)[\\/]/,
        name: 'react',
        chunks: 'all',
        priority: 20
      },
      
      // Router chunks
      router: {
        test: /[\\/]node_modules[\\/](react-router|react-router-dom)[\\/]/,
        name: 'router',
        chunks: 'all',
        priority: 15
      },
      
      // UI library chunks
      ui: {
        test: /[\\/]node_modules[\\/](@mui|@emotion|@chakra-ui)[\\/]/,
        name: 'ui-libs',
        chunks: 'all',
        priority: 12
      },
      
      // Route-based chunks
      dashboard: {
        test: /[\\/]ui[\\/]pages[\\/]Dashboard/,
        name: 'dashboard',
        chunks: 'all',
        priority: 5
      },
      
      articleGeneration: {
        test: /[\\/]ui[\\/]pages[\\/]ArticleGeneration/,
        name: 'article-generation',
        chunks: 'all',
        priority: 5
      },
      
      blogs: {
        test: /[\\/]ui[\\/]pages[\\/]Blogs/,
        name: 'blogs',
        chunks: 'all',
        priority: 5
      },
      
      categories: {
        test: /[\\/]ui[\\/]pages[\\/]Categorias/,
        name: 'categories',
        chunks: 'all',
        priority: 5
      },
      
      prompts: {
        test: /[\\/]ui[\\/]pages[\\/]Prompts/,
        name: 'prompts',
        chunks: 'all',
        priority: 5
      },
      
      monitoring: {
        test: /[\\/]ui[\\/]pages[\\/]Monitoring/,
        name: 'monitoring',
        chunks: 'all',
        priority: 5
      },
      
      security: {
        test: /[\\/]ui[\\/]pages[\\/]Security/,
        name: 'security',
        chunks: 'all',
        priority: 5
      },
      
      pipeline: {
        test: /[\\/]ui[\\/]pages[\\/]Pipeline/,
        name: 'pipeline',
        chunks: 'all',
        priority: 5
      },
      
      // Component chunks
      components: {
        test: /[\\/]ui[\\/]components[\\/]/,
        name: 'components',
        chunks: 'all',
        priority: 8
      },
      
      // Hook chunks
      hooks: {
        test: /[\\/]ui[\\/]hooks[\\/]/,
        name: 'hooks',
        chunks: 'all',
        priority: 8
      },
      
      // Common chunks
      common: {
        name: 'common',
        minChunks: 2,
        chunks: 'all',
        priority: 1,
        reuseExistingChunk: true
      }
    }
  },
  
  // Runtime chunk
  runtimeChunk: {
    name: 'runtime'
  }
};

// ===== DEV SERVER =====

const devServer = {
  static: {
    directory: path.join(__dirname, 'dist')
  },
  compress: true,
  port: 3000,
  hot: true,
  open: true,
  historyApiFallback: true,
  client: {
    overlay: {
      errors: true,
      warnings: false
    }
  },
  headers: {
    'Access-Control-Allow-Origin': '*'
  }
};

// ===== MAIN CONFIG =====

module.exports = {
  mode: isProduction ? 'production' : 'development',
  entry: entryPoints,
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: isProduction ? 'js/[name].[contenthash:8].js' : 'js/[name].js',
    chunkFilename: isProduction ? 'js/[name].[contenthash:8].chunk.js' : 'js/[name].chunk.js',
    publicPath: '/',
    clean: true
  },
  
  resolve: resolveConfig,
  
  module: {
    rules: loaders
  },
  
  plugins,
  
  optimization,
  
  devServer,
  
  devtool: isProduction ? 'source-map' : 'eval-cheap-module-source-map',
  
  performance: {
    hints: isProduction ? 'warning' : false,
    maxEntrypointSize: 512000,
    maxAssetSize: 512000
  },
  
  stats: {
    colors: true,
    modules: false,
    children: false,
    chunks: false,
    chunkModules: false
  },
  
  // Cache para desenvolvimento
  cache: {
    type: 'filesystem',
    buildDependencies: {
      config: [__filename]
    }
  },
  
  // Watch options
  watchOptions: {
    ignored: /node_modules/,
    aggregateTimeout: 300,
    poll: 1000
  }
}; 