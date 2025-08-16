/**
 * Gerenciamento de chave API e modelo
 * @module api_key
 */
import { byId } from './utils.js';

const API_KEY_REGEX = /^[A-Za-z0-9\-_]{16,64}$/;

/**
 * Obtém chave API do input
 * @returns {string}
 */
export const getApiKey = () => byId('api_key') ? byId('api_key').value.trim() : '';

/**
 * Define chave API no input
 * @param {string} key
 */
export const setApiKey = (key) => { if (byId('api_key')) byId('api_key').value = key; };

/**
 * Limpa chave API do input
 */
export const clearApiKey = () => { if (byId('api_key')) byId('api_key').value = ''; };

/**
 * Obtém modelo selecionado
 * @returns {string}
 */
export const getModelType = () => byId('model_type') ? byId('model_type').value : '';

/**
 * Define modelo selecionado
 * @param {string} model
 */
export const setModelType = (model) => { if (byId('model_type')) byId('model_type').value = model; };

/**
 * Limpa modelo selecionado
 */
export const clearModelType = () => { if (byId('model_type')) byId('model_type').value = ''; };

/**
 * Valida chave API
 * @param {string} key
 * @returns {boolean}
 */
export const validateApiKey = (key) => typeof key === 'string' && key.length > 0 && API_KEY_REGEX.test(key); 