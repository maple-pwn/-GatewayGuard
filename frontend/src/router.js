import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from './views/Dashboard.vue'
import Anomaly from './views/Anomaly.vue'
import Chat from './views/Chat.vue'

const routes = [
  { path: '/', name: 'Dashboard', component: Dashboard },
  { path: '/anomaly', name: 'Anomaly', component: Anomaly },
  { path: '/chat', name: 'Chat', component: Chat },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
