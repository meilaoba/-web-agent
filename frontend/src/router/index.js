import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/login', name: 'login', component: () => import('../views/LoginView.vue') },
  {
    path: '/',
    component: () => import('../layout/MainLayout.vue'),
    redirect: '/projects',
    children: [
      { path: 'projects', name: 'projects', component: () => import('../views/ProjectsView.vue') },
      { path: 'projects/:id', name: 'project-detail', component: () => import('../views/ProjectDetailView.vue') },
      { path: 'audit/:taskId', name: 'audit-result', component: () => import('../views/AuditResultView.vue') },
      { path: 'agents/:taskId', name: 'agent-process', component: () => import('../views/AgentProcessView.vue') },
      { path: 'report/:taskId', name: 'report', component: () => import('../views/ReportView.vue') },
      { path: 'rag', name: 'rag-search', component: () => import('../views/RagSearchView.vue') },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// 登录守卫
router.beforeEach((to) => {
  const token = localStorage.getItem('token')
  if (to.path !== '/login' && !token) {
    return { path: '/login' }
  }
  if (to.path === '/login' && token) {
    return { path: '/projects' }
  }
})

export default router
