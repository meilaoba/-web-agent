<template>
  <div>
    <el-card shadow="never">
      <div class="toolbar">
        <h3>项目管理</h3>
        <el-button type="primary" :icon="Plus" @click="dialogVisible = true">新建项目</el-button>
      </div>

      <el-table :data="projects" v-loading="loading" empty-text="暂无项目，请先创建">
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="name" label="项目名称" min-width="160" />
        <el-table-column prop="language" label="语言" width="110">
          <template #default="{ row }">
            <el-tag size="small">{{ row.language || 'unknown' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="file_count" label="文件数" width="90" />
        <el-table-column prop="description" label="描述" min-width="160" show-overflow-tooltip />
        <el-table-column prop="created_at" label="创建时间" width="170" />
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="primary" @click="$router.push(`/projects/${row.id}`)">上传代码 / 审计</el-button>
            <el-popconfirm title="确认删除该项目？" @confirm="removeProject(row.id)">
              <template #reference>
                <el-button size="small" type="danger">删除</el-button>
              </template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" title="新建项目" width="460px">
      <el-form :model="form" label-width="70px">
        <el-form-item label="项目名称" required>
          <el-input v-model="form.name" placeholder="例如：demo-web-app" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" type="textarea" :rows="3" placeholder="项目描述（可选）" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="createProject">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { projectApi } from '../api'

const projects = ref([])
const loading = ref(false)
const dialogVisible = ref(false)
const creating = ref(false)
const form = reactive({ name: '', description: '' })

async function load() {
  loading.value = true
  try {
    const { data } = await projectApi.list()
    projects.value = data
  } catch (e) {
    ElMessage.error('加载项目失败')
  } finally {
    loading.value = false
  }
}

async function createProject() {
  if (!form.name.trim()) {
    ElMessage.warning('请输入项目名称')
    return
  }
  creating.value = true
  try {
    await projectApi.create({ name: form.name, description: form.description })
    ElMessage.success('创建成功')
    dialogVisible.value = false
    form.name = ''
    form.description = ''
    load()
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '创建失败')
  } finally {
    creating.value = false
  }
}

async function removeProject(id) {
  try {
    await projectApi.remove(id)
    ElMessage.success('已删除')
    load()
  } catch (e) {
    ElMessage.error('删除失败')
  }
}

onMounted(load)
</script>

<style scoped>
.toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
</style>
