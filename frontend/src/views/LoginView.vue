<template>
  <div class="login-page">
    <el-card class="login-card">
      <h2 class="title">AI 驱动的 Web 代码安全审计系统</h2>
      <p class="subtitle">AI-Driven Multi-Agent Web Code Security Audit System</p>
      <el-tabs v-model="tab">
        <el-tab-pane label="登录" name="login">
          <el-form :model="loginForm" label-width="70px">
            <el-form-item label="用户名">
              <el-input v-model="loginForm.username" placeholder="用户名" />
            </el-form-item>
            <el-form-item label="密码">
              <el-input v-model="loginForm.password" type="password" show-password placeholder="密码" @keyup.enter="doLogin" />
            </el-form-item>
            <el-button type="primary" style="width: 100%" :loading="loading" @click="doLogin">登 录</el-button>
          </el-form>
        </el-tab-pane>
        <el-tab-pane label="注册" name="register">
          <el-form :model="regForm" label-width="70px">
            <el-form-item label="用户名">
              <el-input v-model="regForm.username" placeholder="至少 3 个字符" />
            </el-form-item>
            <el-form-item label="密码">
              <el-input v-model="regForm.password" type="password" show-password placeholder="至少 6 个字符" />
            </el-form-item>
            <el-button type="primary" style="width: 100%" :loading="loading" @click="doRegister">注 册</el-button>
          </el-form>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { authApi } from '../api'

const router = useRouter()
const tab = ref('login')
const loading = ref(false)
const loginForm = reactive({ username: '', password: '' })
const regForm = reactive({ username: '', password: '' })

async function doLogin() {
  if (!loginForm.username || !loginForm.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }
  loading.value = true
  try {
    const { data } = await authApi.login(loginForm)
    localStorage.setItem('token', data.access_token)
    localStorage.setItem('username', data.user.username)
    ElMessage.success('登录成功')
    router.push('/projects')
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '登录失败')
  } finally {
    loading.value = false
  }
}

async function doRegister() {
  if (regForm.username.length < 3 || regForm.password.length < 6) {
    ElMessage.warning('用户名至少 3 位，密码至少 6 位')
    return
  }
  loading.value = true
  try {
    const { data } = await authApi.register(regForm)
    localStorage.setItem('token', data.access_token)
    localStorage.setItem('username', data.user.username)
    ElMessage.success('注册成功')
    router.push('/projects')
  } catch (e) {
    ElMessage.error(e.response?.data?.detail || '注册失败')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page { height: 100vh; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, #1f3b63 0%, #2e5b9e 100%); }
.login-card { width: 420px; padding: 12px 24px; }
.title { text-align: center; margin-bottom: 4px; }
.subtitle { text-align: center; color: #909399; font-size: 12px; margin-bottom: 16px; }
</style>
