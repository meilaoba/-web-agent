import axios from 'axios'

// Axios 封装：自动附带 Token，统一错误处理
const api = axios.create({
  baseURL: '/api',
  timeout: 120000, // 审计为同步执行，允许较长超时
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (resp) => resp,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  },
)

// ---------- 认证 ----------
export const authApi = {
  register: (data) => api.post('/auth/register', data),
  login: (data) => api.post('/auth/login', data),
}

// ---------- 项目 ----------
export const projectApi = {
  list: () => api.get('/projects'),
  create: (data) => api.post('/projects', data),
  detail: (id) => api.get(`/projects/${id}`),
  upload: (id, file) => {
    const form = new FormData()
    form.append('file', file)
    return api.post(`/projects/${id}/upload`, form, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 300000,
    })
  },
  remove: (id) => api.delete(`/projects/${id}`),
}

// ---------- 审计 ----------
export const auditApi = {
  create: (data) => api.post('/audit/tasks', data),
  list: (projectId) => api.get('/audit/tasks', { params: { project_id: projectId } }),
  detail: (taskId) => api.get(`/audit/tasks/${taskId}`),
  result: (taskId) => api.get(`/audit/tasks/${taskId}/result`),
}

// ---------- 漏洞 ----------
export const vulnApi = {
  list: (taskId) => api.get('/vulnerabilities', { params: { task_id: taskId } }),
  suggestions: (vulnId) => api.get(`/vulnerabilities/${vulnId}/suggestions`),
}

// ---------- Agent 过程 ----------
export const agentApi = {
  logs: (taskId) => api.get(`/agents/tasks/${taskId}/logs`),
}

// ---------- 报告 ----------
export const reportApi = {
  get: (taskId, fmt = 'json') => api.get(`/reports/tasks/${taskId}`, { params: { fmt } }),
}

// ---------- RAG ----------
export const ragApi = {
  search: (data) => api.post('/rag/search', data),
  stats: () => api.get('/rag/stats'),
  // 会话管理
  sessions: () => api.get('/rag/sessions'),
  createSession: (title = '新会话') => api.post('/rag/sessions', { title }),
  messages: (sessionId) => api.get(`/rag/sessions/${sessionId}/messages`),
  deleteSession: (sessionId) => api.delete(`/rag/sessions/${sessionId}`),
  /**
   * RAG 智能对话（SSE 流式）。
   * 返回 async 迭代器，逐个产出事件：
   *   {type:'status', message} | {type:'sources', sources} |
   *   {type:'token', content} | {type:'done', session_id} | {type:'error', message}
   */
  async *chatStream(payload, signal) {
    const token = localStorage.getItem('token')
    const resp = await fetch('/api/rag/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
      signal,
    })
    if (!resp.ok) {
      let detail = `请求失败(${resp.status})`
      try {
        const err = await resp.json()
        if (err.detail) detail = err.detail
      } catch { /* ignore */ }
      throw new Error(detail)
    }
    const reader = resp.body.getReader()
    const decoder = new TextDecoder('utf-8')
    let buffer = ''
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let idx
      while ((idx = buffer.indexOf('\n\n')) >= 0) {
        const raw = buffer.slice(0, idx)
        buffer = buffer.slice(idx + 2)
        const event = parseSseEvent(raw)
        if (event) yield event
      }
    }
  },
}

// 解析单条 SSE 事件文本：event: xxx\ndata: {...}
function parseSseEvent(raw) {
  let type = null
  let data = ''
  for (const line of raw.split('\n')) {
    if (line.startsWith('event:')) type = line.slice(6).trim()
    else if (line.startsWith('data:')) data += line.slice(5).trim()
  }
  if (!type || !data) return null
  try {
    const parsed = JSON.parse(data)
    // sources 事件的 data 是数组（如 [{"title": "CWE-918"}]），直接作为 sources 字段
    if (Array.isArray(parsed)) {
      return { type, sources: parsed }
    }
    // 对象事件（status/sources/done/error）：展开字段
    if (typeof parsed === 'object' && parsed !== null) {
      return { type, ...parsed }
    }
    // token 事件的 data 是 JSON 字符串（如 "判"），作为 content
    return { type, content: parsed }
  } catch {
    return { type, content: data }
  }
}

export default api
