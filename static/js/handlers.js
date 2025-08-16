/**
 * Handlers e inicialização principal
 * @module handlers
 */
import { byId, toast } from './utils.js';
import { apiListBlogs, apiCreateBlog, apiDeleteBlog, apiListPrompts, apiAddPrompt, apiDeletePrompt } from './api.js';
import { renderBlogs, renderPrompts, updatePromptCount } from './render.js';
import { showConfirmModal } from './handlers.js';

let blogs = [];
let selectedBlogIdx = 0;
let prompts = [];

// Painel de logs e métricas
const logs = [];
const metrics = { artigos: 0, falhas: 0, api: 0 };

/**
 * Inicializa a aplicação
 */
export const initApp = async () => {
  try {
    // Dark mode
    const theme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', theme);
    if (byId('theme_toggle')) {
      byId('theme_toggle').onclick = () => {
        const html = document.documentElement;
        const atual = html.getAttribute('data-theme') || 'light';
        const novo = atual === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', novo);
        localStorage.setItem('theme', novo);
      };
    }
    // Blogs
    if (byId('add_blog_btn')) {
      byId('add_blog_btn').onclick = async () => {
        try {
          const nome = prompt('Nome do novo blog/nicho:');
          if (!nome || !nome.trim()) return;
          const desc = prompt('Descrição (opcional):') || '';
          await apiCreateBlog(nome.trim(), desc.trim())
            .catch(err => { showFeedback(err.message || 'Erro ao criar blog.', true); });
          selectedBlogIdx = blogs.length;
          await renderAll();
          toast('Blog criado!');
        } catch (e) { showFeedback(e.message, true); }
      };
    }
    await renderAll();
  } catch (e) {
    toast('Erro crítico na inicialização: ' + e.message, 'error');
  }
};

/**
 * Renderiza blogs e prompts (refatorada para teste)
 * @param {Object} deps - Dependências injetáveis (APIs, renderizadores, utilitários)
 * @param {Object[]} blogsArg
 * @param {number} selectedBlogIdxArg
 * @param {Object[]} promptsArg
 * @returns {Promise<{blogs, selectedBlogIdx, prompts}>}
 */
export async function renderAll(
  deps = {
    apiListBlogs,
    apiDeleteBlog,
    apiListPrompts,
    apiAddPrompt,
    apiDeletePrompt,
    renderBlogs,
    renderPrompts,
    updatePromptCount,
    toast,
    prompt: window.prompt
  },
  blogsArg = [],
  selectedBlogIdxArg = 0,
  promptsArg = []
) {
  let blogs = blogsArg;
  let selectedBlogIdx = selectedBlogIdxArg;
  let prompts = promptsArg;
  blogs = await deps.apiListBlogs();
  await deps.renderBlogs(blogs, selectedBlogIdx, async (idx) => {
    selectedBlogIdx = idx;
    await renderAll(deps, blogs, selectedBlogIdx, prompts);
  }, async (id) => {
    try {
      await deps.apiDeleteBlog(id);
      if (selectedBlogIdx >= blogs.length - 1) selectedBlogIdx = blogs.length - 2;
      await renderAll(deps, blogs, selectedBlogIdx, prompts);
      deps.toast('Blog excluído!');
    } catch (e) { deps.toast(e.message, 'error'); }
  });
  const blog = blogs[selectedBlogIdx];
  if (blog) {
    prompts = await deps.apiListPrompts(blog.id);
    await deps.renderPrompts(prompts, async (p) => {
      const novo = deps.prompt('Editar prompt:', p.text);
      if (novo !== null && novo.trim()) {
        try {
          await deps.apiDeletePrompt(blog.id, p.id);
          await deps.apiAddPrompt(blog.id, novo.trim());
          await renderAll(deps, blogs, selectedBlogIdx, prompts);
          deps.toast('Prompt editado!');
        } catch (e) { deps.toast(e.message, 'error'); }
      }
    }, async (promptId) => {
      try {
        await deps.apiDeletePrompt(blog.id, promptId);
        await renderAll(deps, blogs, selectedBlogIdx, prompts);
        deps.toast('Prompt excluído!');
      } catch (e) { deps.toast(e.message, 'error'); }
    });
    deps.updatePromptCount(prompts.length);
  } else {
    deps.renderPrompts([], () => {}, () => {});
    deps.updatePromptCount(0);
  }
  return { blogs, selectedBlogIdx, prompts };
}

// Modal de confirmação reutilizável
export function showConfirmModal(message, onConfirm) {
  const modal = document.getElementById('confirm_modal');
  const msg = document.getElementById('modal_message');
  const confirmBtn = document.getElementById('modal_confirm_btn');
  const cancelBtn = document.getElementById('modal_cancel_btn');
  msg.textContent = message;
  modal.style.display = 'flex';
  confirmBtn.focus();
  function cleanup() {
    modal.style.display = 'none';
    confirmBtn.removeEventListener('click', onConfirmClick);
    cancelBtn.removeEventListener('click', onCancelClick);
    document.removeEventListener('keydown', onKeyDown);
  }
  function onConfirmClick() {
    cleanup();
    onConfirm();
  }
  function onCancelClick() {
    cleanup();
  }
  function onKeyDown(e) {
    if (e.key === 'Escape') cleanup();
  }
  confirmBtn.addEventListener('click', onConfirmClick);
  cancelBtn.addEventListener('click', onCancelClick);
  document.addEventListener('keydown', onKeyDown);
}
// Exemplo de uso ao excluir blog/prompt:
// showConfirmModal('Deseja excluir este blog?', () => { /* executar exclusão via API */ }); 

function showFeedback(msg, isError = false) {
  const feedback = document.getElementById('feedback_msg');
  if (!feedback) return;
  feedback.textContent = msg;
  feedback.className = 'feedback' + (isError ? ' error' : '');
  feedback.style.display = 'flex';
  setTimeout(() => { feedback.style.display = 'none'; }, isError ? 6000 : 3000);
}

function handleApiError(resp, fallbackMsg = 'Erro inesperado.') {
  if (!resp || !resp.status) {
    showFeedback(fallbackMsg, true);
    return;
  }
  if (resp.status === 401) {
    showFeedback('Autenticação inválida. Verifique sua chave API.', true);
  } else if (resp.status === 403) {
    showFeedback('Permissão negada. Ação não autorizada.', true);
  } else if (resp.status === 429) {
    showFeedback('Limite de uso atingido (quota). Tente novamente mais tarde.', true);
  } else if (resp.status === 408) {
    showFeedback('Timeout de requisição. Verifique sua conexão.', true);
  } else if (resp.status >= 500) {
    showFeedback('Erro interno do servidor. Tente novamente.', true);
  } else {
    resp.json().then(data => showFeedback(data.error || fallbackMsg, true)).catch(() => showFeedback(fallbackMsg, true));
  }
}

// Exemplo de uso em exclusão de blog
function setupBlogDeleteHandlers() {
  const blogList = document.getElementById('blog_list');
  blogList.addEventListener('click', function (e) {
    if (e.target.classList.contains('fa-trash')) {
      const li = e.target.closest('li');
      const blogId = li && li.dataset && li.dataset.blogId;
      if (!blogId) return;
      showConfirmModal('Deseja excluir este blog? Esta ação não pode ser desfeita.', () => {
        fetch(`/api/blogs/${blogId}`, { method: 'DELETE' })
          .then(resp => {
            if (resp.ok) {
              li.remove();
              showFeedback('Blog excluído com sucesso.', false);
            } else {
              handleApiError(resp, 'Erro ao excluir blog.');
            }
          })
          .catch(() => showFeedback('Erro de rede ao excluir blog.', true));
      });
    }
  });
}

// Exemplo de integração para exclusão de prompt
function setupPromptDeleteHandlers() {
  const promptList = document.getElementById('prompt_list');
  promptList.addEventListener('click', function (e) {
    if (e.target.classList.contains('fa-trash')) {
      const li = e.target.closest('li');
      const promptId = li && li.dataset && li.dataset.promptId;
      // Obter blogId selecionado de forma robusta
      let blogId = null;
      const blogList = document.getElementById('blog_list');
      const activeBlog = blogList && blogList.querySelector('li.active');
      if (activeBlog && activeBlog.dataset && activeBlog.dataset.blogId) {
        blogId = activeBlog.dataset.blogId;
      } else if (window.selectedBlogId) {
        blogId = window.selectedBlogId;
      }
      if (!promptId || !blogId) return;
      showConfirmModal('Deseja excluir este prompt?', () => {
        fetch(`/api/blogs/${blogId}/prompts/${promptId}`, { method: 'DELETE' })
          .then(resp => {
            if (resp.ok) {
              li.remove();
              showFeedback('Prompt excluído com sucesso.', false);
            } else {
              handleApiError(resp, 'Erro ao excluir prompt.');
            }
          })
          .catch(() => showFeedback('Erro de rede ao excluir prompt.', true));
      });
    }
  });
}

// Exemplo de uso em adicionar prompt
async function addPrompt(blogId, text) {
  try {
    await apiAddPrompt(blogId, text)
      .catch(err => { showFeedback(err.message || 'Erro ao adicionar prompt.', true); });
    await renderAll();
    showFeedback('Prompt adicionado!', false);
  } catch (e) { showFeedback(e.message, true); }
}

// Exemplo de uso em geração de artigos
function gerarArtigos(blogId) {
  showFeedback('Gerando artigos...', false);
  fetch(`/generate?blog_id=${blogId}`, { method: 'POST' })
    .then(resp => {
      if (resp.ok) {
        showFeedback('Artigos gerados com sucesso!', false);
      } else {
        handleApiError(resp, 'Erro ao gerar artigos.');
      }
    })
    .catch(() => showFeedback('Erro de rede ao gerar artigos.', true));
}

// Exemplo de uso em upload de prompts
function uploadPrompts(blogId, file) {
  const formData = new FormData();
  formData.append('file', file);
  fetch(`/api/blogs/${blogId}/prompts/upload`, { method: 'POST', body: formData })
    .then(resp => {
      if (resp.ok) {
        showFeedback('Prompts importados!', false);
        renderAll();
      } else {
        handleApiError(resp, 'Erro ao importar prompts.');
      }
    })
    .catch(() => showFeedback('Erro de rede ao importar prompts.', true));
}

// Visualização prévia dos artigos gerados
export function showPreviewModal(artigos) {
  let idx = 0;
  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.style = 'display:flex; position:fixed; z-index:9999; left:0; top:0; width:100vw; height:100vh; background:rgba(30,41,59,0.45); align-items:center; justify-content:center;';
  modal.innerHTML = `
    <div class="modal-content" role="dialog" aria-modal="true" style="background:var(--card-bg); border-radius:18px; box-shadow:0 8px 32px rgba(99,102,241,0.18); padding:32px 28px; max-width:600px; margin:auto; text-align:left; min-width:320px; min-height:320px;">
      <h3 style="margin-top:0; color:var(--primary-dark); font-size:1.18rem;">Prévia dos Artigos Gerados</h3>
      <div style="display:flex; gap:12px; align-items:center; margin-bottom:12px;">
        <button id="prev_artigo_btn" style="padding:6px 16px;">&lt;</button>
        <span id="artigo_idx">1/${artigos.length}</span>
        <button id="next_artigo_btn" style="padding:6px 16px;">&gt;</button>
        <input id="artigo_search" type="text" placeholder="Buscar..." style="flex:1; margin-left:18px; padding:6px 12px; border-radius:6px; border:1.5px solid var(--border);">
      </div>
      <pre id="artigo_content" style="background:var(--input-bg); border-radius:8px; padding:18px; max-height:320px; overflow:auto; font-size:1.01rem;">${artigos[0]}</pre>
      <div style="text-align:right; margin-top:18px;"><button id="close_preview_btn" style="background:var(--danger); color:#fff; border:none; border-radius:8px; padding:10px 22px; font-weight:700; cursor:pointer;">Fechar</button></div>
    </div>
  `;
  document.body.appendChild(modal);
  const update = () => {
    modal.querySelector('#artigo_content').textContent = artigos[idx];
    modal.querySelector('#artigo_idx').textContent = `${idx+1}/${artigos.length}`;
  };
  modal.querySelector('#prev_artigo_btn').onclick = () => { if (idx > 0) { idx--; update(); } };
  modal.querySelector('#next_artigo_btn').onclick = () => { if (idx < artigos.length-1) { idx++; update(); } };
  modal.querySelector('#close_preview_btn').onclick = () => { document.body.removeChild(modal); };
  modal.querySelector('#artigo_search').oninput = (e) => {
    const val = e.target.value.toLowerCase();
    const found = artigos.findIndex(a => a.toLowerCase().includes(val));
    if (found >= 0) { idx = found; update(); }
  };
}
// Exemplo de uso após geração:
// showPreviewModal(["Artigo 1...", "Artigo 2..."]);

// Chamar setupBlogDeleteHandlers() e setupPromptDeleteHandlers() na inicialização do app 

export function logAction(msg, tipo = 'info') {
  const now = new Date().toLocaleTimeString();
  logs.unshift(`[${now}] [${tipo.toUpperCase()}] ${msg}`);
  if (logs.length > 50) logs.pop();
  renderLogsPanel();
}

export function incrementMetric(key) {
  if (metrics[key] !== undefined) metrics[key]++;
  renderMetricsPanel();
}

function renderLogsPanel() {
  const panel = document.getElementById('logs_panel');
  if (!panel) return;
  panel.innerHTML = logs.slice(0, 20).map(l => `<div>${l}</div>`).join('') || '<div style="color:#888;">Nenhum log recente.</div>';
}

function renderMetricsPanel() {
  byId('metric_artigos').textContent = metrics.artigos;
  byId('metric_falhas').textContent = metrics.falhas;
  byId('metric_api').textContent = metrics.api;
  // Gráfico simples
  const ctx = byId('metrics_chart').getContext('2d');
  ctx.clearRect(0, 0, 320, 80);
  const total = metrics.artigos + metrics.falhas + metrics.api || 1;
  ctx.fillStyle = '#6366f1';
  ctx.fillRect(10, 60 - (metrics.artigos/total)*60, 40, (metrics.artigos/total)*60);
  ctx.fillStyle = '#ef4444';
  ctx.fillRect(70, 60 - (metrics.falhas/total)*60, 40, (metrics.falhas/total)*60);
  ctx.fillStyle = '#06b6d4';
  ctx.fillRect(130, 60 - (metrics.api/total)*60, 40, (metrics.api/total)*60);
}

export function setupLogsMetricsTabs() {
  const tabLogs = byId('tab_logs');
  const tabMetrics = byId('tab_metrics');
  const logsPanel = byId('logs_panel');
  const metricsPanel = byId('metrics_panel');
  if (!tabLogs || !tabMetrics || !logsPanel || !metricsPanel) return;
  tabLogs.onclick = () => {
    tabLogs.style.background = 'var(--gradient)';
    tabLogs.style.color = '#fff';
    tabMetrics.style.background = 'var(--input-bg)';
    tabMetrics.style.color = 'var(--text)';
    logsPanel.style.display = 'block';
    metricsPanel.style.display = 'none';
  };
  tabMetrics.onclick = () => {
    tabMetrics.style.background = 'var(--gradient)';
    tabMetrics.style.color = '#fff';
    tabLogs.style.background = 'var(--input-bg)';
    tabLogs.style.color = 'var(--text)';
    logsPanel.style.display = 'none';
    metricsPanel.style.display = 'block';
  };
}
// Chamar setupLogsMetricsTabs() na inicialização do app
// Chamar renderLogsPanel() e renderMetricsPanel() após cada ação relevante
// Exemplo: logAction('Blog criado'), incrementMetric('artigos') 

// Onboarding/tutorial visual (tour guiado)
export function startOnboardingTour() {
  const steps = [
    {
      el: '#blog_list',
      msg: 'Aqui você gerencia seus blogs/nichos. Clique em "Novo Blog" para adicionar.'
    },
    {
      el: '#prompt_card',
      msg: 'Adicione prompts manualmente ou faça upload em massa para o blog selecionado.'
    },
    {
      el: '#api_card',
      msg: 'Informe sua chave API e selecione o modelo de IA desejado.'
    },
    {
      el: '#actions_card',
      msg: 'Gere artigos com base nos prompts e acompanhe o progresso.'
    },
    {
      el: '#logs_metrics_card',
      msg: 'Acompanhe logs de ações e métricas de uso nesta área.'
    }
  ];
  let idx = 0;
  let tooltip = null;
  function showStep(i) {
    if (tooltip) tooltip.remove();
    if (i >= steps.length) return;
    const step = steps[i];
    const target = document.querySelector(step.el);
    if (!target) return;
    const rect = target.getBoundingClientRect();
    tooltip = document.createElement('div');
    tooltip.className = 'onboarding-tooltip';
    tooltip.style = `position:fixed; left:${rect.left + rect.width/2 - 160}px; top:${rect.top - 70}px; width:320px; background:var(--card-bg); color:var(--text); border-radius:12px; box-shadow:0 4px 18px rgba(99,102,241,0.13); padding:18px 22px; z-index:10001; font-size:1.08rem; text-align:center;`;
    tooltip.innerHTML = `
      <div style="margin-bottom:12px;">${step.msg}</div>
      <button id="tour_next_btn" style="background:var(--primary); color:#fff; border:none; border-radius:8px; padding:8px 22px; font-weight:700; cursor:pointer; margin-right:8px;">${i < steps.length-1 ? 'Próximo' : 'Finalizar'}</button>
      <button id="tour_skip_btn" style="background:var(--input-bg); color:var(--text); border:none; border-radius:8px; padding:8px 22px; font-weight:700; cursor:pointer;">Pular</button>
    `;
    document.body.appendChild(tooltip);
    document.getElementById('tour_next_btn').onclick = () => { showStep(i+1); };
    document.getElementById('tour_skip_btn').onclick = () => { tooltip.remove(); };
    // Foco acessível
    document.getElementById('tour_next_btn').focus();
  }
  showStep(idx);
}
// Para iniciar o tour: startOnboardingTour();
// Sugestão: adicionar botão "Como usar?" fixo na interface para disparar o tour 

// Inicialização do botão de onboarding
export function setupOnboardingBtn() {
  const btn = document.getElementById('onboarding_btn');
  if (btn) {
    btn.onclick = () => startOnboardingTour();
  }
}
// Chamar setupOnboardingBtn() na inicialização do app 

// Integração SSE/WebSocket para progresso em tempo real
export function connectProgressSSE(traceId, onUpdate) {
  let source = null;
  if (!!window.EventSource) {
    source = new EventSource(`/events/${traceId}`);
    source.onmessage = function (event) {
      try {
        const data = JSON.parse(event.data);
        if (onUpdate) onUpdate(data);
      } catch (e) {}
    };
    source.onerror = function () {
      source.close();
    };
  } else {
    // Fallback para polling
    let stopped = false;
    function poll() {
      if (stopped) return;
      fetch(`/status/${traceId}`)
        .then(resp => resp.json())
        .then(data => { if (onUpdate) onUpdate(data); })
        .catch(() => {});
      setTimeout(poll, 2000);
    }
    poll();
    source = { close: () => { stopped = true; } };
  }
  return source;
}
// Exemplo de uso após iniciar geração:
// connectProgressSSE(traceId, data => { /* atualizar loader, badges, cards */ }); 