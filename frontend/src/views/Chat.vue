<template>
  <div style="height: calc(100vh - 140px); display: flex; flex-direction: column">
    <el-card style="flex: 1; display: flex; flex-direction: column; overflow: hidden">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>AI 安全分析助手</span>
          <el-tag type="info" size="small">会话: {{ sessionId }}</el-tag>
        </div>
      </template>

      <!-- 消息列表 -->
      <div ref="msgBox" style="flex: 1; overflow-y: auto; padding: 10px 0">
        <div
          v-for="(msg, i) in messages"
          :key="i"
          :style="{
            display: 'flex',
            justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start',
            marginBottom: '12px',
          }"
        >
          <div
            :style="{
              maxWidth: '70%',
              padding: '10px 14px',
              borderRadius: '8px',
              background: msg.role === 'user' ? '#409eff' : '#f4f4f5',
              color: msg.role === 'user' ? '#fff' : '#333',
              fontSize: '14px',
              lineHeight: '1.6',
              whiteSpace: 'pre-wrap',
            }"
          >
            {{ msg.content }}
          </div>
        </div>
        <div v-if="loading" style="text-align: center; padding: 12px">
          <el-icon class="is-loading"><Loading /></el-icon>
          <span style="margin-left: 8px; color: #999">AI 正在分析...</span>
        </div>
      </div>

      <!-- 输入区 -->
      <div style="display: flex; gap: 10px; padding-top: 12px; border-top: 1px solid #eee">
        <el-input
          v-model="input"
          placeholder="输入安全分析问题，如：最近有哪些异常事件？"
          @keyup.enter="sendMessage"
          :disabled="loading"
        />
        <el-button type="primary" @click="sendMessage" :loading="loading">
          发送
        </el-button>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, nextTick } from 'vue'
import { Loading } from '@element-plus/icons-vue'
import { llmApi } from '../api/index.js'

const input = ref('')
const messages = ref([])
const loading = ref(false)
const msgBox = ref(null)
const sessionId = ref(Math.random().toString(36).slice(2, 10))

async function sendMessage() {
  const text = input.value.trim()
  if (!text || loading.value) return

  messages.value.push({ role: 'user', content: text })
  input.value = ''
  loading.value = true
  await scrollBottom()

  try {
    const res = await llmApi.chat(text, sessionId.value)
    messages.value.push({
      role: 'assistant',
      content: res.data.response,
    })
  } catch (e) {
    messages.value.push({
      role: 'assistant',
      content: 'LLM 调用失败，请检查后端配置。',
    })
  } finally {
    loading.value = false
    await scrollBottom()
  }
}

async function scrollBottom() {
  await nextTick()
  if (msgBox.value) {
    msgBox.value.scrollTop = msgBox.value.scrollHeight
  }
}
</script>
