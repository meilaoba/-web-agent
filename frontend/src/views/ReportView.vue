<template>
  <div v-loading="loading">
    <el-page-header content="安全审计报告" @back="$router.back()" />
    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <b>{{ report.project?.name || '审计报告' }}</b>
          <el-button size="small" type="primary" :icon="Download" @click="downloadMarkdown">导出 Markdown</el-button>
        </div>
      </template>

      <el-descriptions :column="3" border style="margin-bottom: 16px">
        <el-descriptions-item label="生成时间">{{ report.generated_at }}</el-descriptions-item>
        <el-descriptions-item label="语言">{{ report.project?.language }}</el-descriptions-item>
        <el-descriptions-item label="扫描文件数">{{ report.project?.scanned_files }}</el-descriptions-item>
        <el-descriptions-item label="漏洞总数">{{ report.summary?.total_findings }}</el-descriptions-item>
        <el-descriptions-item label="安全评分">
          <b :style="{ color: scoreColor(report.summary?.security_score) }">{{ report.summary?.security_score }}</b>
        </el-descriptions-item>
        <el-descriptions-item label="等级分布">
          <el-tag v-for="(v, k) in report.summary?.severity_counts" :key="k" size="small"
            :type="severityType(k)" style="margin-right: 4px">{{ k }}:{{ v }}</el-tag>
        </el-descriptions-item>
      </el-descriptions>

      <el-card shadow="never" class="comment-card">
        <b>总体评价：</b>{{ report.overall_comment }}
      </el-card>

      <el-table :data="report.vulnerabilities" empty-text="未发现漏洞">
        <el-table-column label="等级" width="90">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="vulnerability_type" label="类型" min-width="140" />
        <el-table-column prop="cwe_id" label="CWE" width="90" />
        <el-table-column prop="file_path" label="文件" min-width="160" show-overflow-tooltip />
        <el-table-column prop="line" label="行" width="60" />
        <el-table-column prop="repair_suggestion" label="修复建议" min-width="220" show-overflow-tooltip />
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Download } from '@element-plus/icons-vue'
import { reportApi } from '../api'

const route = useRoute()
const taskId = route.params.taskId
const report = ref({})
const loading = ref(false)

const severityType = (s) => ({ Critical: 'danger', High: 'danger', Medium: 'warning', Low: 'info', Info: 'info' }[s] || 'info')
const scoreColor = (s) => (s >= 90 ? '#67c23a' : s >= 70 ? '#e6a23c' : '#f56c6c')

onMounted(async () => {
  loading.value = true
  try {
    const { data } = await reportApi.get(taskId)
    report.value = data
  } catch (e) {
    ElMessage.error('加载报告失败')
  } finally {
    loading.value = false
  }
})

async function downloadMarkdown() {
  try {
    const resp = await reportApi.get(taskId, 'markdown')
    const blob = new Blob([resp.data], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-report-${taskId}.md`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    ElMessage.error('导出失败')
  }
}
</script>

<style scoped>
.comment-card { background: #f0f7ff; margin-bottom: 16px; }
</style>
