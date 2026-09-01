<template>
  <div v-loading="loading">
    <el-page-header content="审计结果 - 漏洞列表" @back="$router.back()" />
    <el-row :gutter="12" style="margin: 16px 0">
      <el-col :span="6">
        <el-card shadow="never" class="stat-card">
          <div class="stat-num">{{ report.summary?.total_findings ?? '-' }}</div>
          <div class="stat-label">漏洞总数</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="stat-card">
          <div class="stat-num">{{ report.summary?.severity_counts?.Critical || 0 }}</div>
          <div class="stat-label">严重</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="stat-card">
          <div class="stat-num">{{ report.summary?.severity_counts?.High || 0 }}</div>
          <div class="stat-label">高危</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="stat-card">
          <div class="stat-num">{{ report.summary?.security_score ?? '-' }}</div>
          <div class="stat-label">安全评分</div>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never">
      <el-table :data="vulns" empty-text="未发现漏洞" @row-click="showDetail">
        <el-table-column label="等级" width="90">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="vulnerability_type" label="漏洞类型" min-width="160" />
        <el-table-column prop="cwe_id" label="CWE" width="100" />
        <el-table-column prop="file_path" label="文件" min-width="180" show-overflow-tooltip />
        <el-table-column prop="line" label="行号" width="80" />
        <el-table-column prop="scanner" label="来源" width="90" />
        <el-table-column prop="reason" label="说明" min-width="200" show-overflow-tooltip />
      </el-table>
    </el-card>

    <el-drawer v-model="drawer" size="60%" :title="current ? `${current.vulnerability_type} @ ${current.file_path}:${current.line}` : ''">
      <template v-if="current">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="风险等级">
            <el-tag :type="severityType(current.severity)" size="small">{{ current.severity }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="CWE">{{ current.cwe_id || '-' }}</el-descriptions-item>
          <el-descriptions-item label="扫描来源">{{ current.scanner }}</el-descriptions-item>
          <el-descriptions-item label="规则">{{ current.rule_id }}</el-descriptions-item>
          <el-descriptions-item label="是否确认" :span="2">{{ current.confirmed ? '已确认' : '未确认' }}</el-descriptions-item>
        </el-descriptions>

        <h4>漏洞原因</h4>
        <p class="text-block">{{ current.reason }}</p>

        <h4>证据（代码片段）</h4>
        <pre class="code-block">{{ current.evidence || '（无）' }}</pre>

        <template v-if="suggestion">
          <h4>修复建议（Repair Agent）</h4>
          <p class="text-block"><b>修复原则：</b>{{ suggestion.principle }}</p>
          <p class="text-block"><b>修复方案：</b>{{ suggestion.suggestion }}</p>
          <p class="text-block"><b>漏洞根因：</b>{{ suggestion.root_cause }}</p>
          <h4>修复后代码示例</h4>
          <pre class="code-block">{{ suggestion.fixed_code || '（无）' }}</pre>
          <el-alert type="info" :closable="false"
            title="修复 Agent 不直接修改原始代码，以上建议需人工确认后应用" style="margin-top: 8px" />
        </template>
        <el-empty v-else description="暂无修复建议" />
      </template>
    </el-drawer>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { auditApi, vulnApi } from '../api'

const route = useRoute()
const taskId = route.params.taskId
const loading = ref(false)
const vulns = ref([])
const report = ref({})
const drawer = ref(false)
const current = ref(null)
const suggestion = ref(null)

const severityType = (s) => ({ Critical: 'danger', High: 'danger', Medium: 'warning', Low: 'info', Info: 'info' }[s] || 'info')

async function load() {
  loading.value = true
  try {
    const [vulnResp, resultResp] = await Promise.all([
      vulnApi.list(taskId),
      auditApi.result(taskId),
    ])
    vulns.value = vulnResp.data
    report.value = resultResp.data.report
  } catch (e) {
    ElMessage.error('加载失败')
  } finally {
    loading.value = false
  }
}

async function showDetail(row) {
  current.value = row
  drawer.value = true
  try {
    const { data } = await vulnApi.suggestions(row.id)
    suggestion.value = data[0] || null
  } catch {
    suggestion.value = null
  }
}

onMounted(load)
</script>

<style scoped>
.stat-card { text-align: center; }
.stat-num { font-size: 28px; font-weight: 700; color: #1f3b63; }
.stat-label { color: #909399; font-size: 13px; margin-top: 4px; }
.text-block { color: #303133; line-height: 1.7; white-space: pre-wrap; }
.code-block { background: #f6f8fa; border: 1px solid #e4e7ed; border-radius: 4px; padding: 12px;
  font-family: Consolas, monospace; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
h4 { margin: 16px 0 8px; }
</style>
