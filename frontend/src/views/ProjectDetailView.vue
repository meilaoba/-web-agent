<template>
  <div v-loading="auditing">
    <el-page-header :content="project.name" @back="$router.push('/projects')" />

    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <b>上传项目代码</b>
      </template>
      <el-upload
        drag
        :auto-upload="false"
        accept=".zip"
        :limit="1"
        :on-change="onFileChange"
        :on-remove="() => (zipFile = null)"
      >
        <el-icon class="el-icon--upload"><UploadFilled /></el-icon>
        <div class="el-upload__text">将项目 zip 包拖到此处，或<em>点击选择</em></div>
        <template #tip>
          <div class="el-upload__tip">支持 Java / Python / JS 等项目的 zip 压缩包，系统将自动解析语言并登记文件。</div>
        </template>
      </el-upload>
      <el-button type="primary" style="margin-top: 12px" :disabled="!zipFile" @click="uploadZip">
        上传并解析
      </el-button>
    </el-card>

    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <b>审计任务</b>
          <el-button type="danger" :disabled="!project.language || project.language === 'unknown'"
            @click="createAudit">
            执行安全审计
          </el-button>
        </div>
      </template>
      <el-alert v-if="!project.language || project.language === 'unknown'" type="info" :closable="false"
        title="请先上传项目代码，系统识别语言后才能执行审计" style="margin-bottom: 12px" />
      <el-table :data="tasks" empty-text="暂无审计记录">
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="task_id" label="任务号" min-width="180" />
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)">{{ statusText(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="scanned_files" label="扫描文件" width="90" />
        <el-table-column prop="total_findings" label="漏洞数" width="80" />
        <el-table-column prop="security_score" label="安全评分" width="90" />
        <el-table-column prop="started_at" label="开始时间" width="170" />
        <el-table-column label="操作" width="260" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="primary" @click="$router.push(`/audit/${row.id}`)">漏洞详情</el-button>
            <el-button size="small" type="warning" @click="$router.push(`/agents/${row.id}`)">Agent 过程</el-button>
            <el-button size="small" type="success" @click="$router.push(`/report/${row.id}`)">报告</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { UploadFilled } from '@element-plus/icons-vue'
import { auditApi, projectApi } from '../api'

const route = useRoute()
const projectId = route.params.id
const project = reactive({ name: '项目', language: '' })
const tasks = ref([])
const zipFile = ref(null)
const auditing = ref(false)

const statusText = (s) => ({ pending: '待处理', running: '执行中', completed: '已完成', failed: '失败' }[s] || s)
const statusType = (s) => ({ pending: 'info', running: 'warning', completed: 'success', failed: 'danger' }[s] || 'info')

function onFileChange(file) {
  zipFile.value = file.raw
}

async function loadProject() {
  const { data } = await projectApi.detail(projectId)
  Object.assign(project, data)
}

async function loadTasks() {
  const { data } = await auditApi.list(projectId)
  tasks.value = data
}

async function uploadZip() {
  if (!zipFile.value) return
  try {
    const { data } = await projectApi.upload(projectId, zipFile.value)
    ElMessage.success(`上传成功：${data.file_count} 个文件（${data.language}）`)
    zipFile.value = null
    loadProject()
    loadTasks()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '上传失败')
  }
}

async function createAudit() {
  auditing.value = true
  try {
    const { data } = await auditApi.create({ project_id: Number(projectId), enable_knowledge: true })
    ElMessage.success(`审计完成：发现 ${data.total_findings} 个漏洞`)
    loadTasks()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '审计失败')
  } finally {
    auditing.value = false
  }
}

onMounted(() => {
  loadProject()
  loadTasks()
})
</script>
