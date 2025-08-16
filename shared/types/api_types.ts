/**
 * Tipos TypeScript compartilhados para API Omni Writer
 * Tracing ID: SHARED_TYPES_20250127_001
 * 
 * Este arquivo contém tipos TypeScript que espelham os schemas Python
 * para garantir consistência entre frontend e backend.
 */

// ============================================================================
// TIPOS BASE
// ============================================================================

export interface BaseEntity {
  id: string;
  created_at: string;
  updated_at: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  trace_id?: string;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination: {
    page: number;
    per_page: number;
    total: number;
    total_pages: number;
  };
}

// ============================================================================
// TIPOS DE BLOG
// ============================================================================

export interface Blog extends BaseEntity {
  title: string;
  content: string;
  author_id?: string;
  status: 'draft' | 'published' | 'archived';
  tags?: string[];
  metadata?: BlogMetadata;
}

export interface BlogCreate {
  title: string;
  content: string;
  author_id?: string;
  tags?: string[];
  metadata?: BlogMetadata;
}

export interface BlogUpdate {
  title?: string;
  content?: string;
  status?: 'draft' | 'published' | 'archived';
  tags?: string[];
  metadata?: BlogMetadata;
}

export interface BlogMetadata {
  seo_title?: string;
  seo_description?: string;
  featured_image?: string;
  reading_time?: number;
  word_count?: number;
}

// ============================================================================
// TIPOS DE CATEGORIA
// ============================================================================

export interface Categoria extends BaseEntity {
  nome: string;
  descricao?: string;
  slug: string;
  parent_id?: string;
  ordem?: number;
  ativo: boolean;
}

export interface CategoriaCreate {
  nome: string;
  descricao?: string;
  slug?: string;
  parent_id?: string;
  ordem?: number;
  ativo?: boolean;
}

export interface CategoriaUpdate {
  nome?: string;
  descricao?: string;
  slug?: string;
  parent_id?: string;
  ordem?: number;
  ativo?: boolean;
}

// ============================================================================
// TIPOS DE PROMPT
// ============================================================================

export interface Prompt extends BaseEntity {
  titulo: string;
  conteudo: string;
  categoria_id?: string;
  tags?: string[];
  tipo: 'artigo' | 'blog' | 'social' | 'email' | 'custom';
  parametros?: PromptParameters;
  ativo: boolean;
}

export interface PromptCreate {
  titulo: string;
  conteudo: string;
  categoria_id?: string;
  tags?: string[];
  tipo: 'artigo' | 'blog' | 'social' | 'email' | 'custom';
  parametros?: PromptParameters;
  ativo?: boolean;
}

export interface PromptUpdate {
  titulo?: string;
  conteudo?: string;
  categoria_id?: string;
  tags?: string[];
  tipo?: 'artigo' | 'blog' | 'social' | 'email' | 'custom';
  parametros?: PromptParameters;
  ativo?: boolean;
}

export interface PromptParameters {
  max_tokens?: number;
  temperature?: number;
  top_p?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
  stop_sequences?: string[];
}

// ============================================================================
// TIPOS DE GERAÇÃO
// ============================================================================

export interface GenerationRequest {
  prompt: string;
  max_tokens?: number;
  temperature?: number;
  top_p?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
  stop_sequences?: string[];
  model?: string;
  stream?: boolean;
}

export interface GenerationResponse {
  content: string;
  trace_id: string;
  model_used: string;
  tokens_used: number;
  finish_reason: string;
  metadata?: GenerationMetadata;
}

export interface GenerationMetadata {
  processing_time: number;
  model_version: string;
  quality_score?: number;
  suggestions?: string[];
}

export interface GenerationStatus {
  status: 'pending' | 'processing' | 'completed' | 'failed';
  progress?: number;
  estimated_time?: number;
  trace_id: string;
  error?: string;
}

// ============================================================================
// TIPOS DE EVENTOS (SSE)
// ============================================================================

export interface GenerationEvent {
  type: 'progress' | 'content' | 'complete' | 'error';
  data: any;
  trace_id: string;
  timestamp: string;
}

export interface ProgressEvent {
  progress: number;
  message: string;
  estimated_time?: number;
}

export interface ContentEvent {
  content: string;
  is_partial: boolean;
}

// ============================================================================
// TIPOS DE AUTENTICAÇÃO
// ============================================================================

export interface AuthRequest {
  email: string;
  password: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: 'Bearer';
  user: User;
}

export interface User extends BaseEntity {
  email: string;
  nome: string;
  role: 'admin' | 'user' | 'editor';
  ativo: boolean;
  preferences?: UserPreferences;
}

export interface UserPreferences {
  theme: 'light' | 'dark' | 'auto';
  language: 'pt-BR' | 'en-US' | 'es-ES';
  notifications: {
    email: boolean;
    push: boolean;
    sms: boolean;
  };
}

// ============================================================================
// TIPOS DE DOWNLOAD
// ============================================================================

export interface DownloadRequest {
  content: string;
  format: 'pdf' | 'docx' | 'txt' | 'html' | 'markdown';
  filename?: string;
  options?: DownloadOptions;
}

export interface DownloadOptions {
  include_header?: boolean;
  include_footer?: boolean;
  page_size?: 'A4' | 'Letter';
  orientation?: 'portrait' | 'landscape';
  margins?: {
    top: number;
    bottom: number;
    left: number;
    right: number;
  };
}

export interface DownloadResponse {
  download_url: string;
  filename: string;
  file_size: number;
  expires_at: string;
}

// ============================================================================
// TIPOS DE WEBHOOK
// ============================================================================

export interface WebhookRequest {
  event_type: 'generation_complete' | 'generation_failed' | 'blog_published';
  data: any;
  timestamp: string;
  signature?: string;
}

export interface WebhookResponse {
  success: boolean;
  message: string;
  received_at: string;
}

// ============================================================================
// TIPOS DE MONITORAMENTO
// ============================================================================

export interface MetricsData {
  timestamp: string;
  endpoint: string;
  method: string;
  status_code: number;
  response_time: number;
  user_agent?: string;
  ip_address?: string;
}

export interface HealthCheck {
  status: 'healthy' | 'degraded' | 'unhealthy';
  checks: {
    database: HealthStatus;
    redis: HealthStatus;
    external_apis: HealthStatus;
  };
  timestamp: string;
  version: string;
}

export interface HealthStatus {
  status: 'up' | 'down';
  response_time?: number;
  error?: string;
}

// ============================================================================
// TIPOS DE VALIDAÇÃO
// ============================================================================

export interface ValidationError {
  field: string;
  message: string;
  code: string;
  value?: any;
}

export interface ValidationResponse {
  valid: boolean;
  errors: ValidationError[];
}

// ============================================================================
// TIPOS DE CONFIGURAÇÃO
// ============================================================================

export interface ApiConfig {
  base_url: string;
  timeout: number;
  retry_attempts: number;
  retry_delay: number;
  headers: Record<string, string>;
}

export interface FeatureFlagConfig {
  name: string;
  status: 'ENABLED' | 'DISABLED' | 'PARTIAL';
  type: 'RELEASE' | 'OPERATIONAL' | 'EXPERIMENTAL' | 'PERMISSION';
  percentage?: number;
  start_date?: string;
  end_date?: string;
  conditions?: Record<string, any>;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface FeatureFlagResponse {
  enabled: boolean;
  config: FeatureFlagConfig;
  metadata: {
    checked_at: string;
    user_id?: string;
    session_id?: string;
  };
}

export interface FeatureFlagsResponse {
  success: boolean;
  data: Record<string, FeatureFlagResponse>;
  trace_id?: string;
  timestamp: string;
}

export interface FeatureFlags {
  enable_streaming: boolean;
  enable_webhooks: boolean;
  enable_analytics: boolean;
  enable_premium_features: boolean;
  // Novas flags de integração
  advanced_generation_enabled: boolean;
  feedback_system_enabled: boolean;
  api_generation_enabled: boolean;
  stripe_payment_enabled: boolean;
  service_mesh_enabled: boolean;
  proactive_intelligence_enabled: boolean;
  contract_drift_prediction_enabled: boolean;
  multi_region_enabled: boolean;
  advanced_caching_enabled: boolean;
  parallel_processing_enabled: boolean;
  enhanced_security_enabled: boolean;
}

// ============================================================================
// UTILITÁRIOS
// ============================================================================

export type ApiMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export type SortOrder = 'asc' | 'desc';

export interface SortOption {
  field: string;
  order: SortOrder;
}

export interface FilterOption {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'contains' | 'in' | 'not_in';
  value: any;
}

export interface QueryParams {
  page?: number;
  per_page?: number;
  sort?: SortOption[];
  filters?: FilterOption[];
  search?: string;
  include?: string[];
}

// ============================================================================
// EXPORTAR TODOS OS TIPOS
// ============================================================================

export type {
  BaseEntity,
  ApiResponse,
  PaginatedResponse,
  Blog,
  BlogCreate,
  BlogUpdate,
  BlogMetadata,
  Categoria,
  CategoriaCreate,
  CategoriaUpdate,
  Prompt,
  PromptCreate,
  PromptUpdate,
  PromptParameters,
  GenerationRequest,
  GenerationResponse,
  GenerationMetadata,
  GenerationStatus,
  GenerationEvent,
  ProgressEvent,
  ContentEvent,
  AuthRequest,
  AuthResponse,
  User,
  UserPreferences,
  DownloadRequest,
  DownloadOptions,
  DownloadResponse,
  WebhookRequest,
  WebhookResponse,
  MetricsData,
  HealthCheck,
  HealthStatus,
  ValidationError,
  ValidationResponse,
  ApiConfig,
  FeatureFlagConfig,
  FeatureFlagResponse,
  FeatureFlagsResponse,
  FeatureFlags,
  ApiMethod,
  SortOrder,
  SortOption,
  FilterOption,
  QueryParams
}; 