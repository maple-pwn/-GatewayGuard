import { createRouter, createWebHistory } from 'vue-router'
import Home from './views/Home.vue'
import Chat from './views/Chat.vue'
import Dashboard from './views/Dashboard.vue'
import Anomaly from './views/Anomaly.vue'
import About from './views/About.vue'

function resolveModeRoute(section) {
  if (typeof window === 'undefined') {
    return `/immersive/${section}`
  }
  const mode = window.localStorage.getItem('gg-ui-mode') || 'immersive'
  return `/${mode}/${section}`
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
  {
    path: '/simple/assistant',
    name: 'SimpleAssistant',
    component: Chat,
    meta: { shell: 'simple', section: 'assistant' },
  },
  {
    path: '/simple/console',
    name: 'SimpleConsole',
    component: Dashboard,
    meta: { shell: 'simple', section: 'console' },
  },
  {
    path: '/simple/events',
    name: 'SimpleEvents',
    component: Anomaly,
    meta: { shell: 'simple', section: 'events' },
  },
  {
    path: '/simple/about',
    name: 'SimpleAbout',
    component: About,
    meta: { shell: 'simple', section: 'about' },
  },
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
