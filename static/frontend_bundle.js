// OmniWriter Frontend Bundle - Integração RESTful Robusta
// Gestão de blogs/nichos, prompts, chave API, integração backend, feedbacks, acessibilidade

// Utilitários
function byId(id) { return document.getElementById(id); }
function qs(sel) { return document.querySelector(sel); }
function qsa(sel) { return Array.from(document.querySelectorAll(sel)); }
function show(el) { if (el) el.style.display = ''; }
function hide(el) { if (el) el.style.display = 'none'; }
function clear(el) { if (el) el.innerHTML = ''; }
function toast(msg, type = 'success') {
  const f = byId('feedback_msg');
  if (!f) return;
  f.textContent = msg;
  f.className = 'feedback' + (type === 'error' ? ' error' : '');
  show(f);
  setTimeout(() => hide(f), 4000);
}

// Estado
let blogs = [];
let selectedBlogIdx = 0;
let prompts = [];

// --- API RESTful ---
async function apiListBlogs() {
  const resp = await fetch('/api/blogs');
  return await resp.json();
}
async function apiCreateBlog(nome, desc) {
  const resp = await fetch('/api/blogs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nome, desc })
  });
  if (!resp.ok) throw new Error((await resp.json()).error || 'Erro ao criar blog');
  return await resp.json();
}
async function apiDeleteBlog(id) {
  const resp = await fetch(`/api/blogs/${id}`, { method: 'DELETE' });
  if (!resp.ok && resp.status !== 404) throw new Error('Erro ao excluir blog');
}
async function apiListPrompts(blog_id) {
  const resp = await fetch(`/api/blogs/${blog_id}/prompts`);
  return await resp.json();
}
async function apiAddPrompt(blog_id, text) {
  const resp = await fetch(`/api/blogs/${blog_id}/prompts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text })
  });
  if (!resp.ok) throw new Error((await resp.json()).error || 'Erro ao adicionar prompt');
  return await resp.json();
}
async function apiDeletePrompt(blog_id, prompt_id) {
  const resp = await fetch(`/api/blogs/${blog_id}/prompts/${prompt_id}`, { method: 'DELETE' });
  if (!resp.ok && resp.status !== 404) throw new Error('Erro ao excluir prompt');
}

// --- Renderização principal ---
async function renderAll() {
  await renderBlogs();
  await renderPrompts();
  // Preencher formulário do blog selecionado
  const blog = blogs[selectedBlogIdx];
  if (byId('blog_nome')) byId('blog_nome').value = blog ? blog.nome : '';
  if (byId('blog_desc')) byId('blog_desc').value = blog ? (blog.desc || '') : '';
  updatePromptCount();
}

// --- Blogs/Nichos ---
async function renderBlogs() {
  blogs = await apiListBlogs();
  const ul = byId('blog_list');
  if (!ul) return;
  clear(ul);
  blogs.forEach((blog, idx) => {
    const li = document.createElement('li');
    li.tabIndex = 0;
    li.className = idx === selectedBlogIdx ? 'active' : '';
    li.innerHTML = `<i class="fa fa-book"></i> <span>${blog.nome}</span> <i class="fa fa-trash" title="Excluir"></i>`;
    li.onclick = async () => { selectedBlogIdx = idx; await renderAll(); };
    li.onkeydown = e => { if (e.key === 'Enter') { selectedBlogIdx = idx; renderAll(); } };
    li.querySelector('.fa-trash').onclick = async ev => {
      ev.stopPropagation();
      try {
        await apiDeleteBlog(blog.id);
        if (selectedBlogIdx >= blogs.length - 1) selectedBlogIdx = blogs.length - 2;
        await renderAll();
        toast('Blog excluído!');
      } catch (e) { toast(e.message, 'error'); }
    };
    ul.appendChild(li);
  });
}

// --- Prompts ---
async function renderPrompts() {
  const blog = blogs[selectedBlogIdx];
  const ul = byId('prompt_list');
  if (!ul || !blog) { if (ul) clear(ul); updatePromptCount(); return; }
  prompts = await apiListPrompts(blog.id);
  clear(ul);
  prompts.forEach((p, idx) => {
    const li = document.createElement('li');
    li.innerHTML = `<i class="fa fa-file-alt"></i> <span>${p.text}</span> <i class="fa fa-pen" title="Editar"></i> <i class="fa fa-trash" title="Excluir"></i>`;
    li.querySelector('.fa-trash').onclick = async () => {
      try {
        await apiDeletePrompt(blog.id, p.id);
        await renderPrompts();
        updatePromptCount();
        toast('Prompt excluído!');
      } catch (e) { toast(e.message, 'error'); }
    };
    li.querySelector('.fa-pen').onclick = async () => {
      const novo = prompt('Editar prompt:', p.text);
      if (novo !== null && novo.trim()) {
        await apiDeletePrompt(blog.id, p.id);
        await apiAddPrompt(blog.id, novo.trim());
        await renderPrompts();
        updatePromptCount();
        toast('Prompt editado!');
      }
    };
    ul.appendChild(li);
  });
  updatePromptCount();
}
function updatePromptCount() {
  const el = byId('prompt_count');
  if (!el) return;
  el.textContent = prompts.length ? `${prompts.length} prompt${prompts.length>1?'s':''}` : '';
}

// --- Inicialização segura ---
window.onload = async function() {
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
          await apiCreateBlog(nome.trim(), desc.trim());
          selectedBlogIdx = blogs.length;
          await renderAll();
          toast('Blog criado!');
        } catch (e) { toast(e.message, 'error'); }
      };
    }
    if (byId('blog_form')) {
      byId('blog_form').onsubmit = async e => {
        e.preventDefault();
        const nome = byId('blog_nome').value.trim();
        const desc = byId('blog_desc').value.trim();
        if (!nome) return toast('Nome do blog/nicho é obrigatório', 'error');
        try {
          const blog = blogs[selectedBlogIdx];
          await apiDeleteBlog(blog.id);
          await apiCreateBlog(nome, desc);
          selectedBlogIdx = blogs.length;
          await renderAll();
          toast('Blog/nicho salvo!');
        } catch (e) { toast(e.message, 'error'); }
      };
    }
    // Prompts
    if (byId('add_prompt_btn')) {
      byId('add_prompt_btn').onclick = async () => {
        const val = byId('prompt_manual').value;
        if (!val.trim()) return toast('Digite ao menos um prompt', 'error');
        const blog = blogs[selectedBlogIdx];
        if (!blog) return toast('Selecione um blog', 'error');
        const lines = val.split('\n').map(l=>l.trim()).filter(Boolean);
        try {
          for (const line of lines) await apiAddPrompt(blog.id, line);
          byId('prompt_manual').value = '';
          await renderPrompts();
          toast('Prompt(s) adicionado(s)!');
        } catch (e) { toast(e.message, 'error'); }
      };
    }
    if (byId('prompt_file')) {
      byId('prompt_file').onchange = async e => {
        const file = e.target.files[0];
        if (!file) return;
        const blog = blogs[selectedBlogIdx];
        if (!blog) return toast('Selecione um blog', 'error');
        const reader = new FileReader();
        reader.onload = async function(ev) {
          const lines = ev.target.result.split(/\r?\n/).map(l=>l.trim()).filter(Boolean);
          try {
            for (const line of lines) await apiAddPrompt(blog.id, line);
            await renderPrompts();
            toast('Prompts carregados!');
          } catch (e) { toast(e.message, 'error'); }
        };
        reader.readAsText(file, 'utf-8');
      };
      byId('prompt_file').parentElement.ondragover = e => { e.preventDefault(); e.currentTarget.style.background = '#e0e7ff'; };
      byId('prompt_file').parentElement.ondragleave = e => { e.preventDefault(); e.currentTarget.style.background = ''; };
      byId('prompt_file').parentElement.ondrop = e => {
        e.preventDefault();
        e.currentTarget.style.background = '';
        const file = e.dataTransfer.files[0];
        if (file) {
          byId('prompt_file').files = e.dataTransfer.files;
          byId('prompt_file').onchange({ target: { files: e.dataTransfer.files } });
        }
      };
    }
    // Geração de artigos
    if (byId('generate_btn')) byId('generate_btn').onclick = () => gerarArtigos(false);
    if (byId('generate_lote_btn')) byId('generate_lote_btn').onclick = () => gerarArtigos(true);
    await renderAll();
  } catch (e) {
    toast('Erro crítico na inicialização: ' + e.message, 'error');
  }
};

// --- Geração de Artigos ---
async function gerarArtigos(lote=false) {
  const blog = blogs[selectedBlogIdx];
  if (!blog || !blog.nome) return toast('Selecione um blog/nicho', 'error');
  const { api_key, model_type } = getApiData();
  if (!api_key) return toast('Chave API obrigatória', 'error');
  byId('loader') && byId('loader').classList.add('active');
  hide(byId('feedback_msg'));
  try {
    let instancias;
    if (lote) {
      const allBlogs = await apiListBlogs();
      instancias = [];
      for (const b of allBlogs.filter(b=>b.id)) {
        const promptsArr = await apiListPrompts(b.id);
        instancias.push({ nome: b.nome, modelo: model_type, api_key, prompts: promptsArr.map(p=>p.text) });
      }
    } else {
      const promptsArr = await apiListPrompts(blog.id);
      instancias = [{ nome: blog.nome, modelo: model_type, api_key, prompts: promptsArr.map(p=>p.text) }];
    }
    const form = new FormData();
    form.append('instancias_json', JSON.stringify(instancias));
    form.append('prompts', instancias[0].prompts.join('\n'));
    form.append('api_key', api_key);
    form.append('model_type', model_type);
    const resp = await fetch('/generate', { method: 'POST', body: form });
    const html = await resp.text();
    document.open(); document.write(html); document.close();
  } catch (e) {
    toast('Erro ao gerar artigos', 'error');
  } finally {
    byId('loader') && byId('loader').classList.remove('active');
  }
}

// --- Chave API e Modelo ---
function getApiData() {
  return {
    api_key: byId('api_key') ? byId('api_key').value.trim() : '',
    model_type: byId('model_type') ? byId('model_type').value : ''
  };
} 