<template>
  <div>
    <el-page-header content="Agent 执行过程" @back="$router.back()" />
    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <b>任务执行链（{{ logs.length }} 步）</b>
      </template>
      <el-timeline v-if="logs.length">
        <el-timeline-item
          v-for="(log, i) in logs"
          :key="i"
          :type="log.status === 'completed' ? 'success' : log.status === 'running' ? 'primary' : 'danger'"
          :timestamp="log.start_time"
          :hollow="log.status !== 'completed'"
        >
          <div class="agent-row">
            <el-tag size="small" :type="agentType(log.agent_name)">{{ agentLabel(log.agent_name) }}</el-tag>
            <span class="duration">耗时 {{ log.duration }}s</span>
          </div>
          <div class="io-block">
            <p class="io-label">输入</p>
            <p class="io-text">{{ log.input_summary }}</p>
          </div>
          <div class="io-block">
            <p class="io-label">输出</p>
            <p class="io-text">{{ log.output_summary }}</p>
          </div>
        </el-timeline-item>
      </el-timeline>
      <el-empty v-else description="暂无执行记录" />
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { agentApi } from '../api'

const route = useRoute()
const taskId = route.params.taskId
const logs = ref([])

const agentLabel = (name) => ({
  orchestrator: 'Orchestrator 主Agent',
  audit_agent: 'Audit 审计Agent',
  knowledge_agent: 'Knowledge 知识Agent',
  repair_agent: 'Repair 修复Agent',
  report_agent: 'Report 报告Agent',
}[name] || name)

const agentType = (name) => ({
  orchestrator: 'danger',
  audit_agent: 'primary',
  knowledge_agent: 'success',
  repair_agent: 'warning',
  report_agent: 'info',
}[name] || 'info')

onMounted(async () => {
  try {
    const { data } = await agentApi.logs(taskId)
    logs.value = data
  } catch (e) {
    ElMessage.error('加载失败')
  }
})
</script>

<style scoped>
.agent-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.duration { color: #909399; font-size: 12px; }
.io-block { background: #f6f8fa; border-radius: 4px; padding: 8px 12px; margin: 6px 0; }
.io-label { font-size: 12px; color: #909399; margin: 0; }
.io-text { font-size: 13px; color: #303133; margin: 2px 0 0; word-break: break-all; }
</style>
