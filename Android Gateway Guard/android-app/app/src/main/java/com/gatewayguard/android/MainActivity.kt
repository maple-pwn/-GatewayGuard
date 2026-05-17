package com.gatewayguard.android

import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder

class MainActivity : ComponentActivity() {

    private var uiState by mutableStateOf(CarUiState())
    private var autoRefreshJob: Job? = null
    private var importResultPanel: CarPanel = CarPanel.Console

    private val backendUrl = "http://127.0.0.1:8000"
    private val defaultRemoteUrl = "http://114.55.164.250:8000"
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val filePicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) {
            cancelImport()
            return@registerForActivityResult
        }
        ioScope.launch {
            val result = runCatching { importUriToBackend(uri) }
                .getOrElse { "{\"error\":${JSONObject.quote(it.message ?: "import failed")}}" }
            pushImportResult(result)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        uiState = uiState.copy(
            backendStatus = getString(R.string.starting_python_backend),
            relayUrl = defaultRemoteUrl
        )
        setContent {
            GatewayGuardCarApp(uiState)
        }
        ioScope.launch { startBackendAndLoadUi() }
    }

    override fun onDestroy() {
        super.onDestroy()
        autoRefreshJob?.cancel()
        ioScope.cancel()
    }

    private suspend fun startBackendAndLoadUi() {
        updateUi { it.copy(backendStatus = getString(R.string.starting_python_backend)) }
        try {
            if (!Python.isStarted()) {
                Python.start(AndroidPlatform(applicationContext))
            }
            val py = Python.getInstance()
            py.getModule("android_entry").callAttr(
                "start_backend",
                filesDir.absolutePath,
                "127.0.0.1",
                8000
            )
        } catch (e: Exception) {
            updateUi {
                it.copy(
                    backendReady = false,
                    backendStatus = getString(
                        R.string.backend_startup_failed,
                        e.message ?: getString(R.string.unknown_error)
                    ),
                    resultTitle = "后端启动失败",
                    resultBody = e.message ?: getString(R.string.unknown_error)
                )
            }
            return
        }

        val ready = waitBackendReady()
        if (ready) {
            updateUi {
                it.copy(
                    backendReady = true,
                    backendStatus = getString(R.string.backend_ready, "$backendUrl/ui/")
                )
            }
            configureDefaultRemoteSync()
            refreshOverview(showResult = false)
            startAutoRefresh()
        } else {
            updateUi {
                it.copy(
                    backendReady = false,
                    backendStatus = getString(
                        R.string.backend_not_ready_detailed,
                        backendFailureDetails()
                    ),
                    resultTitle = "后端尚未就绪",
                    resultBody = backendFailureDetails()
                )
            }
        }
    }

    private fun configureDefaultRemoteSync() {
        ioScope.launch {
            val result = runCatching {
                val payload = relayPayload(enabled = true, deviceName = "Android Gateway (${Build.MODEL})")
                requestText("/api/mobile/sync/config", "POST", payload)
            }
            updateUi {
                val relayStatus = result.fold(
                    onSuccess = { "Relay: 已连接 $defaultRemoteUrl" },
                    onFailure = { "Relay: 自动连接失败 ${it.message ?: "unknown"}" }
                )
                it.copy(relayStatus = relayStatus, relayUrl = defaultRemoteUrl)
            }
        }
    }

    private fun startAutoRefresh() {
        if (autoRefreshJob?.isActive == true) return
        autoRefreshJob = ioScope.launch {
            while (true) {
                refreshOverview(showResult = false)
                delay(5000)
            }
        }
    }

    private suspend fun waitBackendReady(timeoutMs: Long = 60000): Boolean {
        val start = System.currentTimeMillis()
        while (System.currentTimeMillis() - start < timeoutMs) {
            if (isReadyOnce()) return true
            delay(1000)
        }
        return false
    }

    private fun isReadyOnce(): Boolean {
        return runCatching {
            val connection = URI.create("$backendUrl/health/ready").toURL().openConnection() as HttpURLConnection
            connection.connectTimeout = 1500
            connection.readTimeout = 1500
            connection.requestMethod = "GET"
            connection.responseCode in 200..299
        }.getOrDefault(false)
    }

    private fun backendFailureDetails(): String {
        val state = runCatching {
            if (!Python.isStarted()) return@runCatching "Python not started"
            val py = Python.getInstance()
            py.getModule("android_entry").callAttr("get_backend_state_json").toString()
        }.getOrElse {
            "state unavailable: ${it.message}"
        }

        val logTail = runCatching {
            val logFile = File(filesDir, "logs/backend.log")
            if (!logFile.exists()) return@runCatching "log not found: ${logFile.absolutePath}"
            val lines = logFile.readText(Charsets.UTF_8).lines()
            lines.takeLast(30).joinToString("\n")
        }.getOrElse {
            "log read failed: ${it.message}"
        }

        return "state=$state\n\nrecent logs:\n$logTail"
    }

    private fun pickCaptureFile(panel: CarPanel = CarPanel.Console) {
        importResultPanel = panel
        filePicker.launch(arrayOf("*/*"))
    }

    private fun importsDir(): File {
        return File(filesDir, "imports").also { if (!it.exists()) it.mkdirs() }
    }

    private fun scanImportFiles(): List<ImportFile> {
        return importsDir()
            .listFiles()
            ?.filter { it.isFile }
            ?.sortedByDescending { it.lastModified() }
            ?.map { ImportFile(it.name, it.absolutePath, it.length()) }
            ?: emptyList()
    }

    private fun refreshImportFiles(panel: CarPanel = CarPanel.Import) {
        updateUi { it.copy(activePanel = panel, importFiles = scanImportFiles()) }
    }

    private fun showImportPanel() {
        refreshImportFiles(CarPanel.Import)
    }

    private fun importFixedFile(file: ImportFile) {
        runAction("导入固定目录文件", CarPanel.Import) {
            requestText("/api/traffic/import?file_path=${urlEncode(file.path)}", "POST")
        }
    }

    private fun cancelImport() {
        updateUi {
            it.copy(
                activePanel = importResultPanel,
                resultTitle = "导入已取消",
                resultBody = "未选择文件，已取消导入。"
            )
        }
    }

    private suspend fun importUriToBackend(uri: Uri): String {
        val importsDir = importsDir()

        val displayName = queryDisplayName(uri) ?: "capture_${System.currentTimeMillis()}.pcap"
        val safeName = displayName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        val dest = File(importsDir, safeName)

        contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Cannot open selected file" }
            FileOutputStream(dest).use { output -> input.copyTo(output) }
        }

        val encoded = URLEncoder.encode(dest.absolutePath, "UTF-8")
        val body = requestText("/api/traffic/import?file_path=$encoded", "POST")

        updateUi {
            it.copy(
                activePanel = importResultPanel,
                resultTitle = "导入完成",
                resultBody = "${getString(R.string.imported_file_copied, dest.name)}\n\n${friendlyBody(body)}",
                importFiles = scanImportFiles()
            )
        }
        return body
    }

    private fun queryDisplayName(uri: Uri): String? {
        var cursor: Cursor? = null
        return try {
            cursor = contentResolver.query(uri, null, null, null, null)
            if (cursor != null && cursor.moveToFirst()) {
                val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index >= 0) cursor.getString(index) else null
            } else null
        } finally {
            cursor?.close()
        }
    }

    private fun pushImportResult(jsonPayload: String) {
        runOnUiThread {
            uiState = uiState.copy(
                activePanel = importResultPanel,
                resultTitle = "导入结果",
                resultBody = friendlyBody(jsonPayload),
                importFiles = scanImportFiles()
            )
        }
    }

    private fun requestText(path: String, method: String = "GET", payload: JSONObject? = null): String {
        val url = if (path.startsWith("http://") || path.startsWith("https://")) {
            path
        } else {
            "$backendUrl$path"
        }
        val connection = URI.create(url).toURL().openConnection() as HttpURLConnection
        connection.requestMethod = method
        connection.connectTimeout = 5000
        connection.readTimeout = 30000
        connection.setRequestProperty("Accept", "application/json")
        if (payload != null) {
            val bytes = payload.toString().toByteArray(Charsets.UTF_8)
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            connection.outputStream.use { it.write(bytes) }
        }

        val body = if (connection.responseCode in 200..299) {
            connection.inputStream.bufferedReader().use { it.readText() }
        } else {
            connection.errorStream?.bufferedReader()?.use { it.readText() }
                ?: "HTTP ${connection.responseCode}"
        }
        if (connection.responseCode !in 200..299) {
            throw IllegalStateException(body)
        }
        return body
    }

    private fun refreshOverview(showResult: Boolean, panel: CarPanel = CarPanel.Console) {
        if (!uiState.backendReady) {
            if (showResult) showMessage("状态刷新", "后端尚未就绪，请等待启动完成。", panel)
            return
        }
        ioScope.launch {
            val output = runCatching {
                val statsBody = requestText("/api/traffic/stats")
                val alertsBody = requestText("/api/anomaly/events?limit=1")
                val relayBody = runCatching { requestText("/api/mobile/sync/status") }.getOrNull()
                val stats = JSONObject(statsBody)
                val alerts = JSONObject(alertsBody)
                val packetCount = stats.optLong("total_packets", stats.optLong("total", 0)).toString()
                val alertCount = alerts.optLong("total", alerts.optLong("count", 0)).toString()
                val relayStatus = relayBody?.let { formatRelayStatus(it) } ?: uiState.relayStatus
                updateUi {
                    it.copy(
                        packetCount = packetCount,
                        alertCount = alertCount,
                        relayStatus = relayStatus
                    )
                }
                "报文数量：$packetCount\n告警数量：$alertCount\n$relayStatus"
            }.getOrElse {
                "刷新失败：${it.message ?: it.javaClass.simpleName}"
            }
            if (showResult) showMessage("状态刷新", output, panel)
        }
    }

    private fun saveApiKey() {
        val apiKey = uiState.apiKey.trim()
        if (apiKey.isEmpty()) {
            showMessage("写入 API Key", "请输入有效的 OpenAI API Key。")
            return
        }
        runAction("写入 API Key") {
            requestText(
                "/api/system/api-key",
                "POST",
                JSONObject().put("api_key", apiKey).put("provider", "openai")
            )
        }
    }

    private fun simulateTraffic(panel: CarPanel = CarPanel.Console) {
        val scenario = uiState.scenario.trim().ifEmpty { "normal" }
        val count = uiState.simulateCount.trim().ifEmpty { "120" }
        runAction("生成模拟流量", panel) {
            requestText(
                "/api/traffic/simulate?scenario=${urlEncode(scenario)}&count=${urlEncode(count)}",
                "POST"
            )
        }
    }

    private fun trainDetector(panel: CarPanel = CarPanel.Console) {
        runAction("训练 AI 检测器", panel) {
            requestText("/api/anomaly/train?limit=2000", "POST")
        }
    }

    private fun detectAnomalies(panel: CarPanel = CarPanel.Console) {
        runAction("AI 检测流量", panel) {
            requestText("/api/anomaly/detect?limit=500", "POST")
        }
    }

    private fun showTrafficStats() {
        runAction("流量统计") {
            requestText("/api/traffic/stats")
        }
    }

    private fun startRealtimeTraffic(panel: CarPanel = CarPanel.Console) {
        runAction("启动实时流量", panel) {
            requestText("/api/traffic/collect/start?mode=simulator", "POST")
        }
    }

    private fun showRealtimeStatus() {
        runAction("实时流量状态") {
            requestText("/api/traffic/collect/status")
        }
    }

    private fun showSystemStatus() {
        runAction("系统状态") {
            requestText("/api/system/status")
        }
    }

    private fun showLogs() {
        runAction("最近日志", CarPanel.Logs) {
            val body = requestText("/api/system/logs/recent?lines=160")
            runCatching { JSONObject(body).optString("content", body) }.getOrDefault(body)
        }
    }

    private fun testRelay() {
        runAction("Relay 测试") {
            requestText(
                "/api/mobile/sync/test",
                "POST",
                JSONObject().put("target_url", uiState.relayUrl.trim().ifEmpty { defaultRemoteUrl })
            )
        }
    }

    private fun enableRelay(panel: CarPanel = CarPanel.Console) {
        runAction("Relay 同步", panel) {
            requestText("/api/mobile/sync/config", "POST", relayPayload(enabled = true))
        }
    }

    private fun stopRelay() {
        runAction("停止 Relay") {
            requestText("/api/mobile/sync/config", "POST", relayPayload(enabled = false))
        }
    }

    private fun showRelayStatus() {
        runAction("Relay 状态") {
            requestText("/api/mobile/sync/status")
        }
    }

    private fun showAlertsPanel() {
        updateUi { it.copy(activePanel = CarPanel.Alerts, resultTitle = "", resultBody = "") }
        loadAlerts()
    }

    private fun loadAlerts() {
        if (!uiState.backendReady) {
            showMessage("告警列表", "后端尚未就绪，请等待启动完成。", CarPanel.Alerts)
            return
        }
        ioScope.launch {
            val result = runCatching {
                parseAlerts(requestText("/api/anomaly/events?limit=20"))
            }
            updateUi { state ->
                result.fold(
                    onSuccess = { alerts ->
                        state.copy(
                            activePanel = CarPanel.Alerts,
                            alerts = alerts,
                            resultTitle = if (alerts.isEmpty()) "告警列表" else "",
                            resultBody = if (alerts.isEmpty()) "暂无告警。" else ""
                        )
                    },
                    onFailure = {
                        state.copy(
                            activePanel = CarPanel.Alerts,
                            resultTitle = "告警加载失败",
                            resultBody = it.message ?: it.javaClass.simpleName
                        )
                    }
                )
            }
        }
    }

    private fun sendChat() {
        val message = uiState.chatInput.trim()
        if (message.isEmpty()) return
        val sessionId = uiState.chatSessionId
        updateUi {
            it.copy(
                activePanel = CarPanel.Assistant,
                chatInput = "",
                chatMessages = it.chatMessages + ChatMessage("user", message)
            )
        }
        ioScope.launch {
            val result = runCatching {
                val body = requestText(
                    "/api/llm/chat?message=${urlEncode(message)}&session_id=${urlEncode(sessionId)}",
                    "POST"
                )
                val json = JSONObject(body)
                val nextSessionId = json.optString("session_id", sessionId)
                val response = json.optString("response", body)
                nextSessionId to response
            }
            updateUi { state ->
                result.fold(
                    onSuccess = { (nextSessionId, response) ->
                        state.copy(
                            chatSessionId = nextSessionId,
                            chatMessages = state.chatMessages + ChatMessage("assistant", response)
                        )
                    },
                    onFailure = {
                        state.copy(
                            chatMessages = state.chatMessages + ChatMessage(
                                "assistant",
                                "对话请求失败：${it.message ?: it.javaClass.simpleName}"
                            )
                        )
                    }
                )
            }
        }
    }

    private fun resetChat() {
        updateUi {
            it.copy(
                chatSessionId = newSessionId(),
                chatInput = "",
                chatMessages = listOf(
                    ChatMessage("assistant", "已开始新的 AI 助手会话，可以直接提问。")
                )
            )
        }
    }

    private fun relayPayload(enabled: Boolean, deviceName: String = "Android Gateway Compose UI"): JSONObject {
        return JSONObject()
            .put("target_url", uiState.relayUrl.trim().ifEmpty { defaultRemoteUrl })
            .put("enabled", enabled)
            .put("api_key", uiState.relayKey.trim())
            .put("device_name", deviceName)
    }

    private fun runAction(title: String, panel: CarPanel = CarPanel.Console, block: () -> String) {
        updateUi {
            it.copy(activePanel = panel, resultTitle = title, resultBody = "正在执行，请稍候...")
        }
        ioScope.launch {
            val body = runCatching { block() }
            updateUi { state ->
                body.fold(
                    onSuccess = {
                        val summary = resultSummary(title, it)
                        val details = friendlyBody(it)
                        val bodyText = if (details == summary || details.isBlank()) summary else "$summary\n\n$details"
                        state.copy(resultTitle = title, resultBody = bodyText)
                    },
                    onFailure = {
                        state.copy(
                            resultTitle = "$title 失败",
                            resultBody = it.message ?: it.javaClass.simpleName
                        )
                    }
                )
            }
            refreshOverview(showResult = false)
        }
    }

    private fun showMessage(title: String, body: String, panel: CarPanel = CarPanel.Console) {
        updateUi { it.copy(activePanel = panel, resultTitle = title, resultBody = body) }
    }

    private fun returnToDashboard() {
        updateUi { it.copy(activePanel = CarPanel.Dashboard) }
    }

    private fun toggleThemeMode() {
        updateUi { state ->
            state.copy(
                themeMode = if (state.themeMode == ThemeMode.Night) ThemeMode.Day else ThemeMode.Night
            )
        }
    }

    private fun updateUi(transform: (CarUiState) -> CarUiState) {
        runOnUiThread {
            uiState = transform(uiState)
        }
    }

    private fun friendlyBody(body: String): String {
        val trimmed = body.trim()
        if (trimmed.isBlank()) return "操作已完成。"

        runCatching { return formatJsonObject(JSONObject(trimmed)) }
        runCatching { return formatJsonArray(JSONArray(trimmed)) }
        return trimmed
            .lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .take(12)
            .joinToString("\n")
    }

    private fun resultSummary(title: String, body: String): String {
        val json = runCatching { JSONObject(body) }.getOrNull()
        if (json == null) {
            return body.lineSequence().firstOrNull()?.take(120) ?: "操作已完成。"
        }

        return when {
            title.contains("生成模拟流量") -> {
                val generated = json.optLong("generated", json.optLong("count", 0))
                val scenario = json.optString("scenario", uiState.scenario)
                "已生成 $generated 条 $scenario 场景报文。"
            }
            title.contains("训练") -> {
                val packets = json.optLong("packet_count", json.optLong("train_count", 0))
                val trained = json.optBoolean("trained", false)
                if (trained) "检测器训练完成，样本 $packets 条。" else "训练请求已返回，样本 $packets 条。"
            }
            title.contains("检测") -> {
                val detected = json.optLong("detected", json.optLong("total", 0))
                "检测完成，发现 $detected 条异常结果。"
            }
            title.contains("实时流量") || title.contains("启动实时流量") -> {
                val running = json.optBoolean("running", json.optString("status") == "started")
                if (running) "实时流量采集已启动。" else "实时流量状态已更新。"
            }
            title.contains("Relay 测试") -> {
                if (json.optBoolean("ok", false)) {
                    "Relay 测试通过：${json.optString("target_url", uiState.relayUrl)}"
                } else {
                    "Relay 测试失败：${json.optString("error", "unknown")}"
                }
            }
            title.contains("Relay") || title.contains("同步") -> formatRelayStatus(body)
            title.contains("导入") -> "导入操作已返回结果。"
            else -> json.optString("message", json.optString("status", "操作已完成。"))
        }
    }

    private fun formatRelayStatus(body: String): String {
        return runCatching {
            val json = JSONObject(body)
            val queued = json.optLong("queued_packets", 0) + json.optLong("queued_alerts", 0)
            val sent = json.optLong("sent_packets", 0) + json.optLong("sent_alerts", 0)
            val failed = json.optLong("failed_batches", 0)
            val enabled = if (json.optBoolean("enabled", false)) "已开启" else "已停止"
            val error = json.optString("last_error", "")
            if (error.isBlank()) {
                "Relay: $enabled | 队列 $queued | 已发送 $sent | 失败 $failed"
            } else {
                "Relay: $enabled | 队列 $queued | 已发送 $sent | 失败 $failed | $error"
            }
        }.getOrDefault("Relay: 状态未知")
    }

    private fun parseAlerts(body: String): List<AlertItem> {
        val json = JSONObject(body)
        val events = json.optJSONArray("events") ?: JSONArray()
        val alerts = mutableListOf<AlertItem>()
        for (index in 0 until events.length()) {
            val item = events.optJSONObject(index) ?: continue
            val severityRaw = item.optString("severity")
            alerts += AlertItem(
                severity = friendlySeverity(severityRaw),
                severityRank = severityRank(severityRaw),
                type = friendlyAlertType(item.optString("anomaly_type")),
                source = alertNodeText(item.optString("source_node"), item.optString("target_node"), item.optString("protocol")),
                time = friendlyTime(item.optString("timestamp")),
                timestamp = item.optString("timestamp"),
                description = item.optString("description").ifBlank { "检测到异常流量模式。" },
                status = friendlyStatus(item.optString("status")),
                count = item.optLong("packet_count", 0).takeIf { it > 0 }
            )
        }
        return alerts
    }

    private fun friendlySeverity(value: String): String {
        return when (value.lowercase()) {
            "critical", "high" -> "高风险"
            "medium" -> "中风险"
            "low" -> "低风险"
            "info", "informational" -> "提示"
            else -> "未分级"
        }
    }

    private fun severityRank(value: String): Int {
        return when (value.lowercase()) {
            "critical" -> 4
            "high" -> 3
            "medium" -> 2
            "low" -> 1
            else -> 0
        }
    }

    private fun friendlyStatus(value: String): String {
        return when (value.lowercase()) {
            "open", "new", "active" -> "待处理"
            "acknowledged", "ack" -> "已确认"
            "resolved", "closed" -> "已处理"
            else -> "待查看"
        }
    }

    private fun friendlyAlertType(value: String): String {
        return when (value.lowercase()) {
            "replay_suspected" -> "疑似重放攻击"
            "rpm_anomaly", "rpm_spike" -> "转速异常"
            "gear_anomaly", "invalid_gear" -> "挡位异常"
            "ml_auxiliary" -> "疑似异常流量"
            "dos", "dos_attack" -> "疑似拒绝服务攻击"
            "fuzzy", "fuzzing" -> "疑似模糊测试流量"
            "spoofing" -> "疑似伪造流量"
            else -> "异常流量"
        }
    }

    private fun alertNodeText(source: String, target: String, protocol: String): String {
        val nodes = listOf(source, target).filter { it.isNotBlank() && it != "null" }
        val endpoint = if (nodes.isEmpty()) "未知节点" else nodes.joinToString(" → ")
        return if (protocol.isBlank() || protocol == "null") endpoint else "$endpoint / $protocol"
    }

    private fun friendlyTime(value: String): String {
        if (value.isBlank() || value == "null") return "时间未知"
        return value.replace("T", " ").substringBefore(".").take(19)
    }

    private fun visibleAlerts(state: CarUiState): List<AlertItem> {
        val filtered = state.alerts.filter { alert ->
            when (state.alertFilter) {
                AlertFilter.All -> true
                AlertFilter.High -> alert.severityRank >= 3
                AlertFilter.Medium -> alert.severityRank == 2
                AlertFilter.Low -> alert.severityRank == 1
            }
        }
        return when (state.alertSort) {
            AlertSort.Time -> filtered.sortedByDescending { it.timestamp }
            AlertSort.Risk -> filtered.sortedWith(
                compareByDescending<AlertItem> { it.severityRank }.thenByDescending { it.timestamp }
            )
        }
    }

    private fun formatJsonObject(json: JSONObject): String {
        val keys = orderedKeys(json)
        if (keys.isEmpty()) return "没有返回更多信息。"
        return keys.joinToString("\n") { key ->
            "${friendlyKey(key)}：${friendlyValue(json.opt(key))}"
        }
    }

    private fun formatJsonArray(array: JSONArray): String {
        if (array.length() == 0) return "没有记录。"
        val lines = mutableListOf("共 ${array.length()} 条记录。")
        val limit = minOf(array.length(), 5)
        for (index in 0 until limit) {
            val value = array.opt(index)
            val itemText = friendlyValue(value).lineSequence().joinToString("；") { it.trim() }
            lines += "${index + 1}. $itemText"
        }
        if (array.length() > limit) {
            lines += "其余 ${array.length() - limit} 条已省略。"
        }
        return lines.joinToString("\n")
    }

    private fun orderedKeys(json: JSONObject): List<String> {
        val priority = listOf(
            "message", "status", "ok", "error", "last_error",
            "generated", "count", "total", "total_packets", "packet_count",
            "detected", "anomaly_count", "alert_count", "trained", "running",
            "enabled", "queued_packets", "queued_alerts", "sent_packets", "sent_alerts",
            "failed_batches", "scenario", "file", "file_path", "filename", "target_url"
        )
        val keys = mutableListOf<String>()
        val iterator = json.keys()
        while (iterator.hasNext()) {
            keys += iterator.next()
        }
        return priority.filter { keys.contains(it) } + keys.filterNot { priority.contains(it) }.sorted()
    }

    private fun friendlyValue(value: Any?): String {
        return when (value) {
            null, JSONObject.NULL -> "无"
            is Boolean -> if (value) "是" else "否"
            is JSONObject -> formatJsonObject(value).prependIndent("  ").trimStart()
            is JSONArray -> formatJsonArray(value).prependIndent("  ").trimStart()
            is String -> value.ifBlank { "无" }
            else -> value.toString()
        }
    }

    private fun friendlyKey(key: String): String {
        return when (key) {
            "ok" -> "是否成功"
            "message" -> "提示信息"
            "status" -> "状态"
            "error" -> "错误信息"
            "last_error" -> "最近错误"
            "generated" -> "生成数量"
            "count" -> "数量"
            "total" -> "总数"
            "total_packets" -> "总报文数"
            "packet_count" -> "报文数"
            "detected" -> "检测结果数"
            "anomaly_count" -> "异常数量"
            "alert_count" -> "告警数量"
            "trained" -> "是否完成训练"
            "running" -> "是否运行中"
            "enabled" -> "是否启用"
            "queued_packets" -> "待发送报文"
            "queued_alerts" -> "待发送告警"
            "sent_packets" -> "已发送报文"
            "sent_alerts" -> "已发送告警"
            "failed_batches" -> "失败批次"
            "scenario" -> "场景"
            "file" -> "文件"
            "file_path" -> "文件路径"
            "filename" -> "文件名"
            "target_url" -> "目标服务器"
            "provider" -> "服务提供方"
            "session_id" -> "会话编号"
            "response" -> "回复"
            "content" -> "内容"
            else -> key.replace("_", " ")
        }
    }

    private fun urlEncode(value: String): String = URLEncoder.encode(value, "UTF-8")

    @Composable
    private fun GatewayGuardCarApp(state: CarUiState) {
        val palette = paletteFor(state.themeMode)
        MaterialTheme(
            colorScheme = darkColorScheme(
                background = palette.background,
                surface = palette.panel,
                primary = palette.primary,
                secondary = palette.secondary,
                tertiary = palette.info,
                onPrimary = palette.onAccent,
                onSurface = palette.text
            )
        ) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(palette.background)
                    .padding(16.dp)
            ) {
                BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
                    val wide = maxWidth >= 920.dp
                    if (wide) {
                        Row(
                            modifier = Modifier.fillMaxSize(),
                            horizontalArrangement = Arrangement.spacedBy(16.dp)
                        ) {
                            NavigationColumn(state, Modifier.width(260.dp).fillMaxHeight())
                            MainPanel(state, columns = 3, Modifier.weight(1f).fillMaxHeight())
                        }
                    } else {
                        Column(
                            modifier = Modifier.fillMaxSize(),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            TopHeader(state)
                            NavigationRow(state)
                            MainPanel(state, columns = 2, Modifier.weight(1f))
                        }
                    }
                }
            }
        }
    }

    @Composable
    private fun NavigationColumn(state: CarUiState, modifier: Modifier = Modifier) {
        val scroll = rememberScrollState()
        val palette = paletteFor(state.themeMode)

        Surface(
            modifier = modifier,
            shape = RoundedCornerShape(8.dp),
            color = palette.panel
        ) {
            Column(
                modifier = Modifier.padding(16.dp).verticalScroll(scroll),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "GatewayGuard",
                    color = palette.text,
                    fontSize = 30.sp,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "车机安全控制台",
                    color = palette.muted,
                    fontSize = 17.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                StatusPill(state)
                ActionButton(
                    if (state.themeMode == ThemeMode.Night) "切换日间" else "切换夜间",
                    true,
                    Modifier.fillMaxWidth(),
                    secondary = true
                ) { toggleThemeMode() }
                MetricTile("报文", state.packetCount, palette.primary, Modifier.fillMaxWidth())
                MetricTile("告警", state.alertCount, palette.danger, Modifier.fillMaxWidth())
                Surface(shape = RoundedCornerShape(8.dp), color = palette.panelAlt) {
                    Text(
                        text = state.relayStatus,
                        color = palette.muted,
                        fontSize = 15.sp,
                        lineHeight = 20.sp,
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(12.dp)
                    )
                }
                Spacer(modifier = Modifier.height(2.dp))
                NavButton("总览", CarPanel.Dashboard, state.activePanel)
                NavButton("导入", CarPanel.Import, state.activePanel)
                NavButton("告警", CarPanel.Alerts, state.activePanel)
                NavButton("AI 助手", CarPanel.Assistant, state.activePanel)
                NavButton("控制台", CarPanel.Console, state.activePanel)
                NavButton("日志", CarPanel.Logs, state.activePanel)
            }
        }
    }

    @Composable
    private fun NavigationRow(state: CarUiState) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                NavButton("总览", CarPanel.Dashboard, state.activePanel, Modifier.weight(1f))
                NavButton("导入", CarPanel.Import, state.activePanel, Modifier.weight(1f))
                NavButton("告警", CarPanel.Alerts, state.activePanel, Modifier.weight(1f))
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                NavButton("AI", CarPanel.Assistant, state.activePanel, Modifier.weight(1f))
                NavButton("控制台", CarPanel.Console, state.activePanel, Modifier.weight(1f))
                NavButton("日志", CarPanel.Logs, state.activePanel, Modifier.weight(1f))
            }
        }
    }

    @Composable
    private fun TopHeader(state: CarUiState) {
        val palette = paletteFor(state.themeMode)
        Surface(shape = RoundedCornerShape(8.dp), color = palette.panel) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("GatewayGuard 车机控制台", color = palette.text, fontSize = 28.sp, fontWeight = FontWeight.SemiBold)
                StatusPill(state)
                ActionButton(
                    if (state.themeMode == ThemeMode.Night) "切换日间" else "切换夜间",
                    true,
                    Modifier.fillMaxWidth(),
                    secondary = true
                ) { toggleThemeMode() }
            }
        }
    }

    @Composable
    private fun MainPanel(state: CarUiState, columns: Int, modifier: Modifier = Modifier) {
        Surface(
            modifier = modifier,
            shape = RoundedCornerShape(8.dp),
            color = paletteFor(state.themeMode).panel
        ) {
            when (state.activePanel) {
                CarPanel.Dashboard -> DashboardPanel(state, columns)
                CarPanel.Import -> ImportPanel(state)
                CarPanel.Alerts -> AlertsPanel(state)
                CarPanel.Assistant -> AssistantPanel(state)
                CarPanel.Console -> ConsolePanel(state, columns)
                CarPanel.Logs -> LogsPanel(state)
            }
        }
    }

    @Composable
    private fun DashboardPanel(state: CarUiState, columns: Int) {
        val scroll = rememberScrollState()
        val palette = paletteFor(state.themeMode)
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(scroll).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "总览",
                    color = palette.text,
                    fontSize = 34.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f)
                )
                ActionButton("刷新状态", state.backendReady, Modifier.widthIn(min = 160.dp), secondary = true) {
                    refreshOverview(true, CarPanel.Dashboard)
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MetricTile("报文数量", state.packetCount, palette.primary, Modifier.weight(1f))
                MetricTile("告警数量", state.alertCount, palette.danger, Modifier.weight(1f))
                MetricTile("后端状态", if (state.backendReady) "在线" else "启动中", palette.info, Modifier.weight(1f))
            }
            TileGrid(
                columns = columns,
                tiles = listOf(
                    TileSpec("导入数据", "固定目录或系统选择器", palette.primary, state.backendReady) { showImportPanel() },
                    TileSpec("生成模拟流量", "${state.scenario} / ${state.simulateCount.ifBlank { "120" }} 条", palette.secondary, state.backendReady) { simulateTraffic(CarPanel.Dashboard) },
                    TileSpec("启动实时流量", "开启模拟采集器", palette.info, state.backendReady) { startRealtimeTraffic(CarPanel.Dashboard) },
                    TileSpec("训练 AI", "使用最近流量训练检测器", palette.primary, state.backendReady) { trainDetector(CarPanel.Dashboard) },
                    TileSpec("AI 检测", "扫描异常并刷新告警", palette.danger, state.backendReady) { detectAnomalies(CarPanel.Dashboard) },
                    TileSpec("报警列表", "查看最近异常告警", palette.sync, state.backendReady) { showAlertsPanel() }
                )
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ActionButton("打开 AI 助手", true, Modifier.weight(1f), secondary = true) {
                    updateUi { it.copy(activePanel = CarPanel.Assistant) }
                }
                ActionButton("更多控制", state.backendReady, Modifier.weight(1f), secondary = true) {
                    updateUi { it.copy(activePanel = CarPanel.Console) }
                }
            }
            if (state.resultTitle.isNotBlank() || state.resultBody.isNotBlank()) {
                ResultSurface(state.resultTitle, state.resultBody)
            }
        }
    }

    @Composable
    private fun ConfigPanel(state: CarUiState) {
        val palette = paletteFor(state.themeMode)
        Surface(shape = RoundedCornerShape(8.dp), color = palette.panelAlt) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("连接配置", color = palette.text, fontSize = 24.sp, fontWeight = FontWeight.SemiBold)
                LargeTextField(
                    label = "OpenAI API Key",
                    value = state.apiKey,
                    onValueChange = { value -> updateUi { it.copy(apiKey = value) } },
                    password = true
                )
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    ActionButton("写入 API Key", state.backendReady, Modifier.weight(1f)) { saveApiKey() }
                    ActionButton("系统状态", state.backendReady, Modifier.weight(1f)) { showSystemStatus() }
                }
                LargeTextField(
                    label = "Relay Server",
                    value = state.relayUrl,
                    onValueChange = { value -> updateUi { it.copy(relayUrl = value) } }
                )
                LargeTextField(
                    label = "Relay API Key",
                    value = state.relayKey,
                    onValueChange = { value -> updateUi { it.copy(relayKey = value) } },
                    password = true
                )
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    ActionButton("Test", state.backendReady, Modifier.weight(1f)) { testRelay() }
                    ActionButton("Sync", state.backendReady, Modifier.weight(1f)) { enableRelay() }
                    ActionButton("Stop", state.backendReady, Modifier.weight(1f), danger = true) { stopRelay() }
                }
            }
        }
    }

    @Composable
    private fun ImportPanel(state: CarUiState) {
        val palette = paletteFor(state.themeMode)
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            PanelHeader("导入流量")
            Surface(shape = RoundedCornerShape(8.dp), color = palette.panelAlt) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("固定目录", color = palette.text, fontSize = 24.sp, fontWeight = FontWeight.SemiBold)
                    Text(
                        importsDir().absolutePath,
                        color = palette.muted,
                        fontSize = 16.sp,
                        lineHeight = 22.sp
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        ActionButton("刷新列表", true, Modifier.weight(1f), secondary = true) { refreshImportFiles() }
                        ActionButton("系统文件选择器", state.backendReady, Modifier.weight(1f), secondary = true) {
                            pickCaptureFile(CarPanel.Import)
                        }
                    }
                }
            }
            if (state.importFiles.isEmpty()) {
                ResultSurface("导入目录暂无文件", "请将 PCAP、日志或抓包文件放入上方固定目录，或使用系统文件选择器。")
            } else {
                TileGrid(
                    columns = 2,
                    tiles = state.importFiles.map { file ->
                        TileSpec(
                            title = file.name,
                            subtitle = "${file.sizeBytes / 1024} KB",
                            accent = palette.info,
                            enabled = state.backendReady
                        ) { importFixedFile(file) }
                    }
                )
            }
            ResultSurface(state.resultTitle, state.resultBody)
        }
    }

    @Composable
    private fun AlertsPanel(state: CarUiState) {
        val visibleAlerts = visibleAlerts(state)
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            PanelHeader("告警列表")
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ActionButton("刷新告警", state.backendReady, Modifier.weight(1f), secondary = true) { loadAlerts() }
                ActionButton("重新检测", state.backendReady, Modifier.weight(1f), danger = true) { detectAnomalies(CarPanel.Alerts) }
            }
            AlertControls(state, visibleAlerts.size)
            if (state.alerts.isEmpty()) {
                ResultSurface(
                    state.resultTitle.ifBlank { "暂无告警" },
                    state.resultBody.ifBlank { "当前没有异常告警。执行 AI 检测后，可在这里查看最近结果。" }
                )
            } else if (visibleAlerts.isEmpty()) {
                ResultSurface("暂无匹配告警", "当前筛选条件下暂无告警。")
            } else {
                visibleAlerts.forEach { alert ->
                    AlertCard(alert)
                }
            }
            if (state.alerts.isNotEmpty() && (state.resultTitle.isNotBlank() || state.resultBody.isNotBlank())) {
                ResultSurface(state.resultTitle, state.resultBody)
            }
        }
    }

    @Composable
    private fun AlertControls(state: CarUiState, visibleCount: Int) {
        val palette = paletteFor(state.themeMode)
        Surface(shape = RoundedCornerShape(8.dp), color = palette.panelAlt) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("当前显示：$visibleCount 条", color = palette.muted, fontSize = 15.sp, fontWeight = FontWeight.Medium)
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    AlertFilterButton("全部", AlertFilter.All, state.alertFilter, Modifier.weight(1f))
                    AlertFilterButton("高风险", AlertFilter.High, state.alertFilter, Modifier.weight(1f))
                    AlertFilterButton("中风险", AlertFilter.Medium, state.alertFilter, Modifier.weight(1f))
                    AlertFilterButton("低风险", AlertFilter.Low, state.alertFilter, Modifier.weight(1f))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    AlertSortButton("时间优先", AlertSort.Time, state.alertSort, Modifier.weight(1f))
                    AlertSortButton("风险优先", AlertSort.Risk, state.alertSort, Modifier.weight(1f))
                }
            }
        }
    }

    @Composable
    private fun AlertFilterButton(label: String, filter: AlertFilter, current: AlertFilter, modifier: Modifier = Modifier) {
        ActionButton(label, true, modifier, secondary = filter != current) {
            updateUi { it.copy(alertFilter = filter) }
        }
    }

    @Composable
    private fun AlertSortButton(label: String, sort: AlertSort, current: AlertSort, modifier: Modifier = Modifier) {
        ActionButton(label, true, modifier, secondary = sort != current) {
            updateUi { it.copy(alertSort = sort) }
        }
    }

    @Composable
    private fun AlertCard(alert: AlertItem) {
        val palette = paletteFor(uiState.themeMode)
        Surface(shape = RoundedCornerShape(8.dp), color = palette.tile) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    modifier = Modifier.width(6.dp).height(84.dp),
                    shape = RoundedCornerShape(8.dp),
                    color = palette.danger.copy(alpha = 0.86f)
                ) {}
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(alert.severity, color = palette.danger, fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
                        Text(alert.status, color = palette.muted, fontSize = 15.sp, fontWeight = FontWeight.Medium)
                    }
                    Text(alert.type, color = palette.text, fontSize = 22.sp, fontWeight = FontWeight.SemiBold)
                    Text("来源：${alert.source}", color = palette.muted, fontSize = 16.sp, lineHeight = 22.sp)
                    Text("时间：${alert.time}", color = palette.muted, fontSize = 16.sp, lineHeight = 22.sp)
                    alert.count?.let {
                        Text("关联报文：$it 条", color = palette.secondary, fontSize = 16.sp, lineHeight = 22.sp)
                    }
                    Text(alert.description, color = palette.text, fontSize = 16.sp, lineHeight = 23.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
                }
            }
        }
    }

    @Composable
    private fun AssistantPanel(state: CarUiState) {
        Column(
            modifier = Modifier.fillMaxSize().padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            PanelHeader("AI 助手")
            Column(
                modifier = Modifier.weight(1f).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                state.chatMessages.forEach { message ->
                    ChatBubble(message)
                }
            }
            OutlinedTextField(
                value = state.chatInput,
                onValueChange = { value -> updateUi { it.copy(chatInput = value) } },
                modifier = Modifier.fillMaxWidth().heightIn(min = 112.dp),
                textStyle = TextStyle(fontSize = 20.sp, lineHeight = 28.sp),
                label = { Text("输入问题", fontSize = 18.sp) },
                minLines = 2,
                maxLines = 4
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ActionButton("发送", state.backendReady && state.chatInput.isNotBlank(), Modifier.weight(1f)) { sendChat() }
                ActionButton("重置会话", true, Modifier.weight(1f), secondary = true) { resetChat() }
            }
        }
    }

    @Composable
    private fun ConsolePanel(state: CarUiState, columns: Int) {
        val palette = paletteFor(state.themeMode)
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            PanelHeader("控制台")
            ConfigPanel(state)
            ScenarioPanel(state)
            TileGrid(
                columns = columns,
                tiles = listOf(
                    TileSpec("生成模拟流量", "按当前场景生成报文", palette.secondary, state.backendReady) { simulateTraffic() },
                    TileSpec("训练 AI", "使用最近流量训练检测器", palette.primary, state.backendReady) { trainDetector() },
                    TileSpec("AI 检测流量", "扫描并输出异常事件", palette.danger, state.backendReady) { detectAnomalies() },
                    TileSpec("流量统计", "查看报文汇总数据", palette.info, state.backendReady) { showTrafficStats() },
                    TileSpec("实时状态", "查看采集器运行状态", palette.info, state.backendReady) { showRealtimeStatus() },
                    TileSpec("Relay 状态", "查看服务器中转队列", palette.sync, state.backendReady) { showRelayStatus() }
                )
            )
            ResultSurface(state.resultTitle, state.resultBody)
        }
    }

    @Composable
    private fun ScenarioPanel(state: CarUiState) {
        val palette = paletteFor(state.themeMode)
        Surface(shape = RoundedCornerShape(8.dp), color = palette.panelAlt) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("模拟参数", color = palette.text, fontSize = 24.sp, fontWeight = FontWeight.SemiBold)
                TileGrid(
                    columns = 3,
                    tiles = listOf("normal", "dos", "fuzzy", "spoofing", "mixed").map { scenario ->
                        TileSpec(
                            title = scenario,
                            subtitle = if (state.scenario == scenario) "已选择" else "点击选择",
                            accent = if (state.scenario == scenario) palette.primary else palette.buttonSecondary,
                            enabled = true
                        ) {
                            updateUi { it.copy(scenario = scenario) }
                        }
                    }
                )
                LargeTextField(
                    label = "生成数量",
                    value = state.simulateCount,
                    onValueChange = { value -> updateUi { it.copy(simulateCount = value.filter(Char::isDigit)) } }
                )
            }
        }
    }

    @Composable
    private fun LogsPanel(state: CarUiState) {
        Column(
            modifier = Modifier.fillMaxSize().padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            PanelHeader("日志")
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ActionButton("加载最近日志", state.backendReady, Modifier.weight(1f)) { showLogs() }
                ActionButton("系统状态", state.backendReady, Modifier.weight(1f), secondary = true) { showSystemStatus() }
            }
            ResultSurface(state.resultTitle, state.resultBody, Modifier.weight(1f), scrollable = true)
        }
    }

    @Composable
    private fun StatusPill(state: CarUiState) {
        val palette = paletteFor(state.themeMode)
        val color = if (state.backendReady) palette.primary else palette.secondary
        Surface(shape = RoundedCornerShape(8.dp), color = color.copy(alpha = 0.16f)) {
            Text(
                text = state.backendStatus,
                color = color,
                fontSize = 16.sp,
                lineHeight = 22.sp,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                maxLines = 3,
                overflow = TextOverflow.Ellipsis
            )
        }
    }

    @Composable
    private fun MetricTile(label: String, value: String, accent: Color, modifier: Modifier = Modifier) {
        val palette = paletteFor(uiState.themeMode)
        Surface(modifier = modifier.heightIn(min = 104.dp), shape = RoundedCornerShape(8.dp), color = palette.tile) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    label,
                    color = palette.muted,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    value,
                    color = accent,
                    fontSize = 34.sp,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }

    @Composable
    private fun NavButton(label: String, panel: CarPanel, active: CarPanel, modifier: Modifier = Modifier) {
        val palette = paletteFor(uiState.themeMode)
        val selected = panel == active
        Button(
            onClick = {
                if (panel == CarPanel.Alerts) {
                    showAlertsPanel()
                } else {
                    updateUi { it.copy(activePanel = panel) }
                }
            },
            modifier = modifier.fillMaxWidth().heightIn(min = 64.dp),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = if (selected) palette.primary else palette.buttonSecondary,
                contentColor = if (selected) palette.onAccent else palette.text
            )
        ) {
            Text(label, fontSize = 18.sp, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium)
        }
    }

    @Composable
    private fun TileGrid(columns: Int, tiles: List<TileSpec>) {
        val safeColumns = columns.coerceAtLeast(1)
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            tiles.chunked(safeColumns).forEach { row ->
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    row.forEach { tile ->
                        ActionTile(tile, Modifier.weight(1f))
                    }
                    repeat(safeColumns - row.size) {
                        Spacer(modifier = Modifier.weight(1f))
                    }
                }
            }
        }
    }

    @Composable
    private fun ActionTile(tile: TileSpec, modifier: Modifier = Modifier) {
        val palette = paletteFor(uiState.themeMode)
        val tileContainer = if (uiState.themeMode == ThemeMode.Day) {
            palette.tile
        } else {
            palette.tileSoft
        }
        val titleColor = if (tile.enabled) palette.text else palette.buttonDisabledText
        val subtitleColor = if (tile.enabled) tile.accent else palette.buttonDisabledText
        Button(
            onClick = tile.onClick,
            enabled = tile.enabled,
            modifier = modifier.fillMaxWidth().heightIn(min = 112.dp),
            shape = RoundedCornerShape(8.dp),
            contentPadding = PaddingValues(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = tileContainer,
                contentColor = palette.text,
                disabledContainerColor = palette.buttonDisabled,
                disabledContentColor = palette.buttonDisabledText
            )
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    modifier = Modifier.width(6.dp).height(52.dp),
                    shape = RoundedCornerShape(8.dp),
                    color = if (tile.enabled) tile.accent.copy(alpha = 0.82f) else palette.buttonDisabledText.copy(alpha = 0.45f)
                ) {}
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text(
                        tile.title,
                        color = titleColor,
                        fontSize = 21.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        tile.subtitle,
                        color = subtitleColor,
                        fontSize = 15.sp,
                        lineHeight = 21.sp,
                        fontWeight = FontWeight.Medium,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }

    @Composable
    private fun ActionButton(
        label: String,
        enabled: Boolean,
        modifier: Modifier = Modifier,
        secondary: Boolean = false,
        danger: Boolean = false,
        onClick: () -> Unit
    ) {
        val palette = paletteFor(uiState.themeMode)
        val color = when {
            danger -> palette.danger
            secondary -> palette.buttonSecondary
            else -> palette.primary
        }
        Button(
            onClick = onClick,
            enabled = enabled,
            modifier = modifier.heightIn(min = 68.dp),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = color,
                contentColor = if (secondary) palette.text else palette.onAccent,
                disabledContainerColor = palette.buttonDisabled,
                disabledContentColor = palette.buttonDisabledText
            )
        ) {
            Text(label, fontSize = 18.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }

    @Composable
    private fun PanelHeader(title: String) {
        val palette = paletteFor(uiState.themeMode)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(
                title,
                color = palette.text,
                fontSize = 32.sp,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            ActionButton("返回总览", true, Modifier.widthIn(min = 150.dp), secondary = true) { returnToDashboard() }
        }
    }

    @Composable
    private fun LargeTextField(
        label: String,
        value: String,
        onValueChange: (String) -> Unit,
        password: Boolean = false
    ) {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier.fillMaxWidth().heightIn(min = 72.dp),
            label = { Text(label, fontSize = 16.sp) },
            singleLine = true,
            textStyle = TextStyle(fontSize = 18.sp),
            visualTransformation = if (password) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None
        )
    }

    @Composable
    private fun ResultSurface(
        title: String,
        body: String,
        modifier: Modifier = Modifier,
        scrollable: Boolean = false
    ) {
        if (title.isBlank() && body.isBlank()) return

        val lines = body.lines()
        val summary = lines.firstOrNull().orEmpty()
        val detail = lines.drop(1).joinToString("\n").trim()
        val contentModifier = if (scrollable) {
            Modifier.padding(16.dp).verticalScroll(rememberScrollState())
        } else {
            Modifier.padding(16.dp)
        }
        val palette = paletteFor(uiState.themeMode)
        Surface(
            modifier = modifier.fillMaxWidth().heightIn(min = 180.dp),
            shape = RoundedCornerShape(8.dp),
            color = palette.panelAlt
        ) {
            Column(
                modifier = contentModifier,
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(title, color = palette.text, fontSize = 24.sp, fontWeight = FontWeight.SemiBold)
                if (summary.isNotBlank()) {
                    Text(
                        summary,
                        color = palette.primary,
                        fontSize = 20.sp,
                        lineHeight = 28.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
                if (detail.isNotBlank()) {
                    Text(
                        detail,
                        color = palette.text,
                        fontSize = 16.sp,
                        lineHeight = 24.sp
                    )
                }
            }
        }
    }

    @Composable
    private fun ChatBubble(message: ChatMessage) {
        val palette = paletteFor(uiState.themeMode)
        val isUser = message.role == "user"
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
            color = if (isUser) palette.primary.copy(alpha = 0.22f) else palette.panelAlt
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    if (isUser) "分析员" else "AI 助手",
                    color = if (isUser) palette.primary else palette.info,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(message.content, color = palette.text, fontSize = 19.sp, lineHeight = 28.sp)
            }
        }
    }
}

private enum class CarPanel {
    Dashboard,
    Import,
    Alerts,
    Assistant,
    Console,
    Logs
}

private data class ChatMessage(
    val role: String,
    val content: String
)

private data class TileSpec(
    val title: String,
    val subtitle: String,
    val accent: Color,
    val enabled: Boolean = true,
    val onClick: () -> Unit
)

private data class ImportFile(
    val name: String,
    val path: String,
    val sizeBytes: Long
)

private data class AlertItem(
    val severity: String,
    val severityRank: Int,
    val type: String,
    val source: String,
    val time: String,
    val timestamp: String,
    val description: String,
    val status: String,
    val count: Long?
)

private enum class AlertFilter {
    All,
    High,
    Medium,
    Low
}

private enum class AlertSort {
    Time,
    Risk
}

private enum class ThemeMode {
    Night,
    Day
}

private data class CarPalette(
    val background: Color,
    val panel: Color,
    val panelAlt: Color,
    val tile: Color,
    val tileSoft: Color,
    val text: Color,
    val muted: Color,
    val primary: Color,
    val secondary: Color,
    val info: Color,
    val danger: Color,
    val sync: Color,
    val buttonSecondary: Color,
    val buttonDisabled: Color,
    val buttonDisabledText: Color,
    val onAccent: Color
)

private fun paletteFor(mode: ThemeMode): CarPalette {
    return when (mode) {
        ThemeMode.Night -> CarPalette(
            background = Color(0xFF101820),
            panel = Color(0xFF172330),
            panelAlt = Color(0xFF203040),
            tile = Color(0xFF223243),
            tileSoft = Color(0xFF263848),
            text = Color(0xFFE7EEF4),
            muted = Color(0xFFB2C0CC),
            primary = Color(0xFF54C6A3),
            secondary = Color(0xFFE2B85B),
            info = Color(0xFF84A7D8),
            danger = Color(0xFFE07076),
            sync = Color(0xFFA9A0E8),
            buttonSecondary = Color(0xFF46596A),
            buttonDisabled = Color(0xFF2D3A46),
            buttonDisabledText = Color(0xFF8795A1),
            onAccent = Color(0xFF071512)
        )
        ThemeMode.Day -> CarPalette(
            background = Color(0xFFE9EEF3),
            panel = Color(0xFFFFFFFF),
            panelAlt = Color(0xFFF4F7FA),
            tile = Color(0xFFF9FBFC),
            tileSoft = Color(0xFFEFF4F7),
            text = Color(0xFF18232D),
            muted = Color(0xFF5F6F7D),
            primary = Color(0xFF2E8F75),
            secondary = Color(0xFFC29132),
            info = Color(0xFF4F78A8),
            danger = Color(0xFFC85F66),
            sync = Color(0xFF7468B6),
            buttonSecondary = Color(0xFFD8E1EA),
            buttonDisabled = Color(0xFFE1E7ED),
            buttonDisabledText = Color(0xFF84919C),
            onAccent = Color(0xFFFFFFFF)
        )
    }
}

private data class CarUiState(
    val backendStatus: String = "正在启动后端...",
    val backendReady: Boolean = false,
    val relayStatus: String = "Relay: 等待后端启动",
    val relayUrl: String = "http://114.55.164.250:8000",
    val relayKey: String = "",
    val apiKey: String = "",
    val packetCount: String = "0",
    val alertCount: String = "0",
    val resultTitle: String = "",
    val resultBody: String = "",
    val activePanel: CarPanel = CarPanel.Dashboard,
    val importFiles: List<ImportFile> = emptyList(),
    val alerts: List<AlertItem> = emptyList(),
    val alertFilter: AlertFilter = AlertFilter.All,
    val alertSort: AlertSort = AlertSort.Time,
    val themeMode: ThemeMode = ThemeMode.Night,
    val scenario: String = "normal",
    val simulateCount: String = "120",
    val chatInput: String = "",
    val chatSessionId: String = newSessionId(),
    val chatMessages: List<ChatMessage> = listOf(
        ChatMessage("assistant", "车机大屏 UI 已就绪。后端启动完成后，可以询问当前流量、告警或同步状态。")
    )
)

private fun newSessionId(): String {
    return System.currentTimeMillis().toString(36)
}
