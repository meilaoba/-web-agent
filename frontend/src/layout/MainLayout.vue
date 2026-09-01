<template>
  <el-container class="layout">
    <el-aside width="220px" class="aside">
      <div class="logo">
        <el-icon :size="22"><Lock /></el-icon>
        <span>AI 代码安全审计</span>
      </div>
      <el-menu :default-active="activeMenu" router background-color="#1f3b63" text-color="#cfd8e6"
        active-text-color="#ffffff" class="menu">
        <el-menu-item index="/projects">
          <el-icon><Folder /></el-icon><span>项目管理</span>
        </el-menu-item>
        <el-menu-item index="/rag">
          <el-icon><Search /></el-icon><span>RAG 知识库</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <div class="header-title">{{ pageTitle }}</div>
        <el-dropdown @command="onCommand">
          <span class="user-chip">
            <el-icon><User /></el-icon> {{ username }}
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="logout">退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>
      <el-main class="main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Folder, Search, Lock, User } from '@element-plus/icons-vue'

const route = useRoute()
const router = useRouter()

const username = localStorage.getItem('username') || '用户'
const activeMenu = computed(() => {
  if (route.path.startsWith('/projects')) return '/projects'
  if (route.path.startsWith('/rag')) return '/rag'
  return route.path
})
const pageTitle = computed(() => {
  const map = {
    '/projects': '项目管理',
    '/rag': 'RAG 知识库',
  }
  if (route.path.includes('/audit/')) return '审计结果'
  if (route.path.includes('/agents/')) return 'Agent 执行过程'
  if (route.path.includes('/report/')) return '安全报告'
  return map[activeMenu.value] || 'AI 代码安全审计系统'
})

function onCommand(cmd) {
  if (cmd === 'logout') {
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    ElMessage.success('已退出登录')
    router.push('/login')
  }
}
</script>

<style scoped>
.layout { height: 100vh; }
.aside { background: #1f3b63; }
.logo { display: flex; align-items: center; gap: 8px; color: #fff; font-size: 16px; font-weight: 600; padding: 18px 16px; }
.menu { border-right: none; }
.header { background: #fff; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.header-title { font-size: 16px; font-weight: 600; color: #303133; }
.user-chip { display: inline-flex; align-items: center; gap: 4px; cursor: pointer; color: #409eff; }
.main { padding: 20px; overflow-y: auto; }
</style>
