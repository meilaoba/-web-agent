<template>
  <div class="chat-layout">
    <!-- 左侧：会话列表 -->
    <div class="session-panel">
      <div class="session-head">
        <b>会话列表</b>
        <el-button type="primary" size="small" :icon="Plus" @click="newSession">新建</el-button>
      </div>
      <div class="session-list">
        <div
          v-for="s in sessions"
          :key="s.id"
          class="session-item"
          :class="{ active: s.id === currentSessionId }"
          @click="switchSession(s)"
        >
          <span class="session-title">{{ s.title }}</span>
          <el-icon class="session-del" @click.stop="removeSession(s)"><Close /></el-icon>
        </div>
        <el-empty v-if="!sessions.length" description="暂无会话" :image-size="60" />
      </div>
      <div class="session-foot">
        <el-tag v-if="stats" size="small" type="info">知识库 {{ stats.chunk_count }} Chunks</el-tag>
      </div>
    </div>

    <!-- 右侧：对话区 -->
    <div class="chat-panel">
      <div class="chat-header">
        <div>
          <b>RAG 安全知识库智能助手</b>
          <span class="sub">检索增强 · 上下文记忆 · 流式回答</span>
        </div>
        <div class="topk-setting">
          <span class="opt-label">Top-K</span>
          <el-input-number v-model="topK" :min="1" :max="20" size="small" />
        </div>
      </div>

      <div class="chat-body" ref="chatBody">
        <div v-if="!messages.length" class="chat-welcome">
          <div class="welcome-icon">🛡️</div>
          <p>我是 RAG 安全知识库智能助手</p>
          <p class="welcome-tip">可以问我：什么是SSRF？Java 如何防止 SQL 注入？XSS 怎么修复？</p>
        </div>

        <div v-for="(m, idx) in messages" :key="idx" class="msg" :class="m.role">
          <div class="avatar" :class="m.role">{{ m.role === 'user' ? '我' : 'AI' }}</div>
          <div class="bubble" :class="m.role">
            <div class="status-line" v-if="m.streaming && streamStatus && !m.content">
              <el-icon class="is-loading"><Loading /></el-icon> {{ streamStatus }}
            </div>
            <div class="markdown" v-html="renderMarkdown(m.content)"></div>
            <div class="status-line" v-if="m.streaming && streamStatus && m.content">{{ streamStatus }}</div>

            <!-- 参考知识：仅本次使用了 RAG 时显示 -->
            <div v-if="m.usedRag && m.sources && m.sources.length" class="sources">
              <div class="sources-title" @click="m.showSources = !m.showSources">
                📚 参考知识（{{ m.sources.length }} 条）
                <el-icon><ArrowDown v-if="!m.showSources" /><ArrowUp v-else /></el-icon>
              </div>
              <div v-show="m.showSources" class="sources-body">
                <div v-for="(src, si) in m.sources" :key="si" class="source-item">
                  <el-tag size="small" type="danger" v-if="src.title">{{ src.title }}</el-tag>
                  <span class="source-doc">{{ src.document }}</span>
                  <span class="source-score">score {{ src.score }}</span>
                  <div class="source-preview">{{ src.preview }}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="chat-input">
        <el-input
          v-model="input"
          type="textarea"
          :rows="2"
          resize="none"
          placeholder="输入安全问题，Enter 发送，Shift+Enter 换行"
          :disabled="generating"
          @keydown.enter.exact.prevent="send"
          @keydown.shift.enter=""
        />
        <div class="input-actions">
          <el-button v-if="generating" type="warning" :icon="VideoPause" @click="stopGenerate">停止</el-button>
          <el-button v-else type="primary" :icon="Promotion" :disabled="!input.trim()" @click="send">发送</el-button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { ArrowDown, ArrowUp, Close, Loading, Plus, Promotion, VideoPause } from '@element-plus/icons-vue'
import { ragApi } from '../api'
import { renderMarkdown } from '../utils/markdown'

const route = useRoute()
const sessions = ref([])
const currentSessionId = ref(null)
const messages = ref([])
const input = ref('')
const topK = ref(5)
const stats = ref(null)
const generating = ref(false)
const streamStatus = ref('')
const chatBody = ref(null)
let abortController = null

// ---------- 会话管理 ----------
async function loadSessions() {
  try {
    const { data } = await ragApi.sessions()
    sessions.value = data
  } catch {
    sessions.value = []
  }
}

async function newSession() {
  try {
    const { data } = await ragApi.createSession()
    sessions.value.unshift(data)
    currentSessionId.value = data.id
    messages.value = []
  } catch {
    ElMessage.error('创建会话失败')
  }
}

async function switchSession(s) {
  currentSessionId.value = s.id
  messages.value = []
  try {
    const { data } = await ragApi.messages(s.id)
    // 转换历史消息：assistant 消息无 sources 信息（历史中不保存来源，仅正文）
    messages.value = data.map((m) => ({
      role: m.role,
      content: m.content,
      sources: null,
      showSources: false,
    }))
  } catch {
    ElMessage.error('加载会话历史失败')
  }
  scrollToBottom()
}

async function removeSession(s) {
  try {
    await ragApi.deleteSession(s.id)
    sessions.value = sessions.value.filter((x) => x.id !== s.id)
    if (currentSessionId.value === s.id) {
      currentSessionId.value = null
      messages.value = []
    }
  } catch {
    ElMessage.error('删除会话失败')
  }
}

// ---------- 对话 ----------
async function send() {
  const text = input.value.trim()
  if (!text || generating.value) return
  input.value = ''
  generating.value = true
  streamStatus.value = '正在检索知识库...'
  abortController = new AbortController()

  messages.value.push({ role: 'user', content: text, sources: null, showSources: false })
  const aiMsg = { role: 'assistant', content: '', sources: null, showSources: true, usedRag: false, streaming: true }
  messages.value.push(aiMsg)
  scrollToBottom()

  try {
    for await (const event of ragApi.chatStream(
      { message: text, session_id: currentSessionId.value, top_k: topK.value },
      abortController.signal,
    )) {
      if (event.type === 'meta') {
        aiMsg.usedRag = !!event.used_rag
        if (!aiMsg.usedRag) streamStatus.value = '正在生成回答...'
      } else if (event.type === 'status') {
        streamStatus.value = event.message
      } else if (event.type === 'sources') {
        aiMsg.sources = event.sources
      } else if (event.type === 'token') {
        aiMsg.content += event.content
        scrollToBottom(true)
      } else if (event.type === 'done') {
        currentSessionId.value = event.session_id
        await loadSessions()
      } else if (event.type === 'error') {
        aiMsg.content = aiMsg.content || ''
        ElMessage.error(event.message || '生成失败')
      }
    }
  } catch (e) {
    if (e.name === 'AbortError') {
      ElMessage.info('已停止生成')
    } else {
      ElMessage.error(e.message || '对话请求失败，请检查后端服务')
    }
  } finally {
    aiMsg.streaming = false
    generating.value = false
    streamStatus.value = ''
    abortController = null
    scrollToBottom()
  }
}

function stopGenerate() {
  if (abortController) abortController.abort()
}

// ---------- 滚动 ----------
function scrollToBottom(force = false) {
  nextTick(() => {
    const el = chatBody.value
    if (el) el.scrollTop = el.scrollHeight
  })
}

watch(messages, () => scrollToBottom())

onMounted(async () => {
  try {
    const { data } = await ragApi.stats()
    stats.value = data
  } catch { /* 后端未启动时静默 */ }
  await loadSessions()
  // 支持通过路由参数恢复指定会话（页面刷新后）
  const sid = route.query.session
  if (sid) {
    const s = sessions.value.find((x) => x.id === Number(sid))
    if (s) switchSession(s)
  }
})

onBeforeUnmount(() => {
  if (abortController) abortController.abort()
})
</script>

<style scoped>
.chat-layout { display: flex; height: calc(100vh - 100px); gap: 12px; }

/* 左侧会话面板 */
.session-panel { width: 240px; background: #fff; border: 1px solid #ebeef5; border-radius: 8px;
  display: flex; flex-direction: column; overflow: hidden; }
.session-head { display: flex; justify-content: space-between; align-items: center; padding: 12px; border-bottom: 1px solid #f0f2f5; }
.session-list { flex: 1; overflow-y: auto; padding: 8px; }
.session-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 10px;
  border-radius: 6px; cursor: pointer; margin-bottom: 4px; }
.session-item:hover { background: #f5f7fa; }
.session-item.active { background: #ecf5ff; }
.session-title { flex: 1; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.session-del { color: #c0c4cc; display: none; }
.session-item:hover .session-del { display: inline-flex; }
.session-del:hover { color: #f56c6c; }
.session-foot { padding: 10px 12px; border-top: 1px solid #f0f2f5; }

/* 右侧对话面板 */
.chat-panel { flex: 1; background: #fff; border: 1px solid #ebeef5; border-radius: 8px;
  display: flex; flex-direction: column; overflow: hidden; }
.chat-header { display: flex; justify-content: space-between; align-items: center;
  padding: 14px 18px; border-bottom: 1px solid #f0f2f5; }
.sub { color: #909399; font-size: 12px; margin-left: 10px; }
.topk-setting { display: flex; align-items: center; gap: 8px; }
.opt-label { color: #606266; font-size: 13px; }

/* 消息区 */
.chat-body { flex: 1; overflow-y: auto; padding: 18px; background: #fafbfc; }
.chat-welcome { text-align: center; margin-top: 15%; color: #909399; }
.welcome-icon { font-size: 44px; }
.welcome-tip { font-size: 13px; margin-top: 6px; }

.msg { display: flex; margin-bottom: 16px; }
.msg.user { flex-direction: row-reverse; }
.avatar { width: 34px; height: 34px; border-radius: 8px; display: flex; align-items: center;
  justify-content: center; font-size: 13px; flex-shrink: 0; }
.avatar.user { background: #409eff; color: #fff; }
.avatar.assistant { background: #1f3b63; color: #fff; }
.bubble { max-width: 78%; padding: 10px 14px; border-radius: 8px; font-size: 14px; line-height: 1.7; }
.bubble.user { background: #ecf5ff; margin-right: 10px; }
.bubble.assistant { background: #fff; border: 1px solid #ebeef5; margin-left: 10px; }
.status-line { display: flex; align-items: center; gap: 6px; color: #909399; font-size: 13px; }

/* Markdown 内容 */
.markdown :deep(p) { margin: 4px 0; }
.markdown :deep(h1), .markdown :deep(h2), .markdown :deep(h3), .markdown :deep(h4) { margin: 10px 0 6px; }
.markdown :deep(code) { background: #f0f2f5; padding: 1px 5px; border-radius: 4px; font-size: 13px;
  font-family: Consolas, monospace; }
.markdown :deep(pre.code-block) { background: #f6f8fa; border: 1px solid #e4e7ed; border-radius: 6px;
  padding: 12px; overflow-x: auto; }
.markdown :deep(pre.code-block code) { background: none; padding: 0; }
.markdown :deep(ul), .markdown :deep(ol) { padding-left: 22px; margin: 4px 0; }
.markdown :deep(a) { color: #409eff; }
.markdown :deep(blockquote) { border-left: 3px solid #d9d9d9; padding-left: 10px; color: #606266; margin: 6px 0; }

/* 参考知识 */
.sources { margin-top: 10px; border-top: 1px dashed #e4e7ed; padding-top: 8px; }
.sources-title { font-size: 13px; color: #606266; cursor: pointer; display: flex; align-items: center; gap: 4px; }
.sources-body { margin-top: 8px; }
.source-item { background: #fafafa; border: 1px solid #f0f2f5; border-radius: 6px; padding: 8px 10px; margin-bottom: 6px; }
.source-item .el-tag { margin-right: 6px; }
.source-doc { font-size: 12px; color: #606266; }
.source-score { font-size: 12px; color: #909399; margin-left: 8px; }
.source-preview { font-size: 12px; color: #909399; margin-top: 4px; overflow: hidden;
  text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; }

/* 输入区 */
.chat-input { border-top: 1px solid #f0f2f5; padding: 12px 14px; background: #fff; }
.input-actions { display: flex; justify-content: flex-end; margin-top: 8px; }
</style>
