import { z } from 'zod';

// Schema para Blog baseado em app/main.py
export const BlogSchema = z.object({
  id: z.number().int().positive(),
  nome: z.string().min(1).max(40),
  desc: z.string().max(80).optional()
});

// Schema para Prompt baseado em app/main.py
export const PromptSchema = z.object({
  id: z.number().int().positive(),
  text: z.string().min(1).max(500).trim()
});

// Schema para Generation Request baseado em app/main.py
export const GenerationRequestSchema = z.object({
  api_key: z.string().min(1),
  model_type: z.enum(['openai', 'deepseek']),
  prompts: z.array(z.string().min(1).max(500)),
  temperature: z.number().min(0.0).max(2.0).default(0.7),
  max_tokens: z.number().int().min(256).max(8192).default(4096),
  language: z.string().default('pt-BR')
});

// Schema para Generation Response baseado em app/main.py
export const GenerationResponseSchema = z.object({
  download_link: z.string().url(),
  trace_id: z.string().uuid().optional()
});

// Schema para Status Response baseado em app/main.py
export const StatusResponseSchema = z.object({
  trace_id: z.string().uuid(),
  status: z.enum(['pending', 'processing', 'completed', 'failed']),
  total: z.number().int().positive(),
  current: z.number().int().min(0)
});

// Schema para Error Response baseado em app/main.py
export const ErrorResponseSchema = z.object({
  error: z.string().min(1)
});

// Schema para Webhook Request baseado em app/main.py
export const WebhookRequestSchema = z.object({
  url: z.string().url()
});

// Schema para Webhook Response baseado em app/main.py
export const WebhookResponseSchema = z.object({
  status: z.literal('ok')
});

// Type exports
export type Blog = z.infer<typeof BlogSchema>;
export type Prompt = z.infer<typeof PromptSchema>;
export type GenerationRequest = z.infer<typeof GenerationRequestSchema>;
export type GenerationResponse = z.infer<typeof GenerationResponseSchema>;
export type StatusResponse = z.infer<typeof StatusResponseSchema>;
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
export type WebhookRequest = z.infer<typeof WebhookRequestSchema>;
export type WebhookResponse = z.infer<typeof WebhookResponseSchema>;

// Validation functions
export const validateBlog = (data: unknown): Blog => BlogSchema.parse(data);
export const validatePrompt = (data: unknown): Prompt => PromptSchema.parse(data);
export const validateGenerationRequest = (data: unknown): GenerationRequest => GenerationRequestSchema.parse(data);
export const validateGenerationResponse = (data: unknown): GenerationResponse => GenerationResponseSchema.parse(data);
export const validateStatusResponse = (data: unknown): StatusResponse => StatusResponseSchema.parse(data);
export const validateErrorResponse = (data: unknown): ErrorResponse => ErrorResponseSchema.parse(data);
export const validateWebhookRequest = (data: unknown): WebhookRequest => WebhookRequestSchema.parse(data);
export const validateWebhookResponse = (data: unknown): WebhookResponse => WebhookResponseSchema.parse(data); 