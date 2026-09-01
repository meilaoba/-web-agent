// 轻量 Markdown 渲染（用于 AI 回答展示）
// 安全：先转义 HTML（防止 LLM 输出中的 <script> 等注入），再应用 Markdown 规则
// 支持：代码块 / 行内代码 / 标题 / 粗体 / 斜体 / 列表 / 链接 / 引用 / 分段

function escapeHtml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function inline(text) {
  let t = text
  // 行内代码（先保护，避免内部被其他规则处理）
  const codes = []
  t = t.replace(/`([^`]+)`/g, (m, c) => {
    codes.push(c)
    return `\u0000CODE${codes.length - 1}\u0000`
  })
  // 链接
  t = t.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
  // 粗体
  t = t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
  // 斜体
  t = t.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, '$1<em>$2</em>')
  // 恢复行内代码
  t = t.replace(/\u0000CODE(\d+)\u0000/g, (m, i) => `<code>${escapeHtml(codes[Number(i)])}</code>`)
  return t
}

export function renderMarkdown(src) {
  if (!src) return ''
  const lines = escapeHtml(src).split('\n')
  const html = []
  let i = 0
  let inList = false
  let listType = null
  const closeList = () => {
    if (inList) {
      html.push(`</${listType}>`)
      inList = false
      listType = null
    }
  }

  while (i < lines.length) {
    const line = lines[i]
    // 代码块
    if (/^```/.test(line)) {
      closeList()
      const lang = line.slice(3).trim()
      const buf = []
      i++
      while (i < lines.length && !/^```/.test(lines[i])) {
        buf.push(lines[i])
        i++
      }
      html.push(`<pre class="code-block"><code>${buf.join('\n')}</code></pre>`)
      i++ // 跳过闭合 ```
      continue
    }
    // 标题
    const h = line.match(/^(#{1,4})\s+(.*)$/)
    if (h) {
      closeList()
      html.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`)
      i++
      continue
    }
    // 引用
    if (/^&gt;\s?/.test(line)) {
      closeList()
      html.push(`<blockquote>${inline(line.replace(/^&gt;\s?/, ''))}</blockquote>`)
      i++
      continue
    }
    // 无序列表
    const ul = line.match(/^[-*]\s+(.*)$/)
    if (ul) {
      if (!inList || listType !== 'ul') {
        closeList()
        html.push('<ul>')
        inList = true
        listType = 'ul'
      }
      html.push(`<li>${inline(ul[1])}</li>`)
      i++
      continue
    }
    // 有序列表
    const ol = line.match(/^\d+\.\s+(.*)$/)
    if (ol) {
      if (!inList || listType !== 'ol') {
        closeList()
        html.push('<ol>')
        inList = true
        listType = 'ol'
      }
      html.push(`<li>${inline(ol[1])}</li>`)
      i++
      continue
    }
    // 空行：结束列表
    if (!line.trim()) {
      closeList()
      i++
      continue
    }
    // 普通段落
    closeList()
    html.push(`<p>${inline(line)}</p>`)
    i++
  }
  closeList()
  return html.join('\n')
}
