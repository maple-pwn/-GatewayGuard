import { createRouter, createWebHistory } from 'vue-router'
import Home from './views/Home.vue'
import Chat from './views/Chat.vue'
import Dashboard from './views/Dashboard.vue'
import Anomaly from './views/Anomaly.vue'
import About from './views/About.vue'

function resolveModeRoute(section) {
  return `/immersive/${section}`
}

const routes = [
  {
    path: '/',
    name: 'Home',
    component: Home,
    meta: { shell: 'landing' },
  },
  { path: '/assistant', redirect: () => resolveModeRoute('assistant') },
  { path: '/console', redirect: () => resolveModeRoute('console') },
  { path: '/events', redirect: () => resolveModeRoute('events') },
  { path: '/about', redirect: () => resolveModeRoute('about') },
  { path: '/simple/:section', redirect: (to) => `/immersive/${to.params.section}` },
  {
    path: '/immersive/assistant',
    name: 'ImmersiveAssistant',
    component: Chat,
    meta: { shell: 'immersive', section: 'assistant' },
  },
  {
    path: '/immersive/console',
    name: 'ImmersiveConsole',
    component: Dashboard,
    meta: { shell: 'immersive', section: 'console' },
  },
  {
    path: '/immersive/events',
    name: 'ImmersiveEvents',
    component: Anomaly,
    meta: { shell: 'immersive', section: 'events' },
  },
  {
    path: '/immersive/about',
    name: 'ImmersiveAbout',
    component: About,
    meta: { shell: 'immersive', section: 'about' },
  },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
