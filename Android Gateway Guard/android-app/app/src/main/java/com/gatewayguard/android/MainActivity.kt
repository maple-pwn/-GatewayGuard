package com.gatewayguard.android

import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
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

    private var webView: WebView? = null
    private var uiState by mutableStateOf(CarUiState())
    private var autoRefreshJob: Job? = null

    private val backendUrl = "http://127.0.0.1:8000"
    private val defaultRemoteUrl = "http://114.55.164.250:8000"
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val filePicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) {
            pushImportResult("{\"error\":\"No file selected\"}")
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
        webView?.destroy()
        webView = null
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
            loadWebUiIfAvailable()
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

    private fun configureWebView(view: WebView) {
        view.settings.javaScriptEnabled = true
        view.settings.domStorageEnabled = true
        view.webViewClient = WebViewClient()
        view.webChromeClient = WebChromeClient()
        view.addJavascriptInterface(AndroidBridge(this), "AndroidBridge")
    }

    private fun loadWebUiIfAvailable() {
        runOnUiThread {
            webView?.loadUrl("$backendUrl/ui/")
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

    private fun pickCaptureFile() {
        filePicker.launch(arrayOf("*/*"))
    }

    private suspend fun importUriToBackend(uri: Uri): String {
        val importsDir = File(filesDir, "imports")
        if (!importsDir.exists()) importsDir.mkdirs()

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
                activePanel = CarPanel.Console,
                resultTitle = "导入完成",
                resultBody = "${getString(R.string.imported_file_copied, dest.name)}\n\n${prettyBody(body)}"
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
        val quoted = JSONObject.quote(jsonPayload)
        runOnUiThread {
            webView?.evaluateJavascript("window.onNativeImportResult($quoted);", null)
            uiState = uiState.copy(
                activePanel = CarPanel.Console,
                resultTitle = "导入结果",
                resultBody = prettyBody(jsonPayload)
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

    private fun refreshOverview(showResult: Boolean) {
        if (!uiState.backendReady) {
            if (showResult) showMessage("状态刷新", "后端尚未就绪，请等待启动完成。")
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
            if (showResult) showMessage("状态刷新", output)
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

    private fun simulateTraffic() {
        val scenario = uiState.scenario.trim().ifEmpty { "normal" }
        val count = uiState.simulateCount.trim().ifEmpty { "120" }
        runAction("生成模拟流量") {
            requestText(
                "/api/traffic/simulate?scenario=${urlEncode(scenario)}&count=${urlEncode(count)}",
                "POST"
            )
        }
    }

    private fun trainDetector() {
        runAction("训练 AI 检测器") {
            requestText("/api/anomaly/train?limit=2000", "POST")
        }
    }

    private fun detectAnomalies() {
        runAction("AI 检测流量") {
            requestText("/api/anomaly/detect?limit=500", "POST")
        }
    }

    private fun showTrafficStats() {
        runAction("流量统计") {
            requestText("/api/traffic/stats")
        }
    }

    private fun startRealtimeTraffic() {
        runAction("启动实时流量") {
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

    private fun enableRelay() {
        runAction("Relay 同步") {
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
                        val formatted = prettyBody(it)
                        state.copy(resultTitle = title, resultBody = formatted)
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

    private fun updateUi(transform: (CarUiState) -> CarUiState) {
        runOnUiThread {
            uiState = transform(uiState)
        }
    }

    private fun prettyBody(body: String): String {
        return runCatching { JSONObject(body).toString(2) }
            .recoverCatching { JSONArray(body).toString(2) }
            .getOrDefault(body)
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

    private fun urlEncode(value: String): String = URLEncoder.encode(value, "UTF-8")

    @Composable
    private fun GatewayGuardCarApp(state: CarUiState) {
        MaterialTheme(
            colorScheme = darkColorScheme(
                background = Color(0xFF0E141C),
                surface = Color(0xFF17212D),
                primary = Color(0xFF35D0A5),
                secondary = Color(0xFFFFC857),
                tertiary = Color(0xFF7AA2FF),
                onPrimary = Color(0xFF061915),
                onSurface = Color(0xFFEAF2F8)
            )
        ) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        Brush.linearGradient(
                            listOf(Color(0xFF0E141C), Color(0xFF13233A), Color(0xFF101820))
                        )
                    )
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
        Surface(
            modifier = modifier,
            shape = RoundedCornerShape(8.dp),
            color = Color(0xE617212D)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "GatewayGuard",
                    color = Color.White,
                    fontSize = 30.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "车机安全控制台",
                    color = Color(0xFFB9C8D8),
                    fontSize = 18.sp
                )
                StatusPill(state)
                MetricTile("报文", state.packetCount, Color(0xFF35D0A5))
                MetricTile("告警", state.alertCount, Color(0xFFFF6B6B))
                Text(
                    text = state.relayStatus,
                    color = Color(0xFFB9C8D8),
                    fontSize = 15.sp,
                    lineHeight = 20.sp,
                    maxLines = 4,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(4.dp))
                NavButton("总览磁贴", CarPanel.Dashboard, state.activePanel)
                NavButton("AI 助手", CarPanel.Assistant, state.activePanel)
                NavButton("控制台", CarPanel.Console, state.activePanel)
                NavButton("日志", CarPanel.Logs, state.activePanel)
                NavButton("原 Web 面板", CarPanel.Web, state.activePanel)
            }
        }
    }

    @Composable
    private fun NavigationRow(state: CarUiState) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                NavButton("总览", CarPanel.Dashboard, state.activePanel, Modifier.weight(1f))
                NavButton("AI", CarPanel.Assistant, state.activePanel, Modifier.weight(1f))
                NavButton("控制台", CarPanel.Console, state.activePanel, Modifier.weight(1f))
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                NavButton("日志", CarPanel.Logs, state.activePanel, Modifier.weight(1f))
                NavButton("Web", CarPanel.Web, state.activePanel, Modifier.weight(1f))
            }
        }
    }

    @Composable
    private fun TopHeader(state: CarUiState) {
        Surface(shape = RoundedCornerShape(8.dp), color = Color(0xE617212D)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("GatewayGuard 车机控制台", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.Bold)
                StatusPill(state)
            }
        }
    }

    @Composable
    private fun MainPanel(state: CarUiState, columns: Int, modifier: Modifier = Modifier) {
        Surface(
            modifier = modifier,
            shape = RoundedCornerShape(8.dp),
            color = Color(0xCC111A24)
        ) {
            when (state.activePanel) {
                CarPanel.Dashboard -> DashboardPanel(state, columns)
                CarPanel.Assistant -> AssistantPanel(state)
                CarPanel.Console -> ConsolePanel(state, columns)
                CarPanel.Logs -> LogsPanel(state)
                CarPanel.Web -> WebPanel(state)
            }
        }
    }

    @Composable
    private fun DashboardPanel(state: CarUiState, columns: Int) {
        val scroll = rememberScrollState()
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(scroll).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("触控磁贴", color = Color.White, fontSize = 32.sp, fontWeight = FontWeight.Bold)
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MetricTile("报文数量", state.packetCount, Color(0xFF35D0A5), Modifier.weight(1f))
                MetricTile("告警数量", state.alertCount, Color(0xFFFF6B6B), Modifier.weight(1f))
                MetricTile("后端", if (state.backendReady) "在线" else "启动中", Color(0xFF7AA2FF), Modifier.weight(1f))
            }
            TileGrid(
                columns = columns,
                tiles = listOf(
                    TileSpec("导入数据", "选择 PCAP、日志或抓包文件", Color(0xFF35D0A5), state.backendReady) { pickCaptureFile() },
                    TileSpec("刷新状态", "更新报文、告警和 Relay", Color(0xFF7AA2FF), state.backendReady) { refreshOverview(true) },
                    TileSpec("启动实时流量", "开启模拟采集器并同步", Color(0xFFFFC857), state.backendReady) { startRealtimeTraffic() },
                    TileSpec("同步到服务器", "连接 $defaultRemoteUrl", Color(0xFF35D0A5), state.backendReady) { enableRelay() },
                    TileSpec("AI 助手", "大字号对话分析", Color(0xFFB58CFF), true) {
                        updateUi { it.copy(activePanel = CarPanel.Assistant) }
                    },
                    TileSpec("原 Web 面板", "保留旧版完整页面入口", Color(0xFF8AD8FF), state.backendReady) {
                        updateUi { it.copy(activePanel = CarPanel.Web) }
                        loadWebUiIfAvailable()
                    }
                )
            )
            ConfigPanel(state)
            ResultSurface(state.resultTitle, state.resultBody)
        }
    }

    @Composable
    private fun ConfigPanel(state: CarUiState) {
        Surface(shape = RoundedCornerShape(8.dp), color = Color(0xFF172636)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("连接配置", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
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
    private fun AssistantPanel(state: CarUiState) {
        Column(
            modifier = Modifier.fillMaxSize().padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Text("AI 助手", color = Color.White, fontSize = 32.sp, fontWeight = FontWeight.Bold)
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
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("控制台磁贴", color = Color.White, fontSize = 32.sp, fontWeight = FontWeight.Bold)
            ScenarioPanel(state)
            TileGrid(
                columns = columns,
                tiles = listOf(
                    TileSpec("生成模拟流量", "按当前场景生成报文", Color(0xFFFFC857), state.backendReady) { simulateTraffic() },
                    TileSpec("训练 AI", "使用最近流量训练检测器", Color(0xFF35D0A5), state.backendReady) { trainDetector() },
                    TileSpec("AI 检测流量", "扫描并输出异常事件", Color(0xFFFF6B6B), state.backendReady) { detectAnomalies() },
                    TileSpec("流量统计", "查看报文汇总数据", Color(0xFF7AA2FF), state.backendReady) { showTrafficStats() },
                    TileSpec("实时状态", "查看采集器运行状态", Color(0xFF8AD8FF), state.backendReady) { showRealtimeStatus() },
                    TileSpec("Relay 状态", "查看服务器中转队列", Color(0xFFB58CFF), state.backendReady) { showRelayStatus() }
                )
            )
            ResultSurface(state.resultTitle, state.resultBody)
        }
    }

    @Composable
    private fun ScenarioPanel(state: CarUiState) {
        Surface(shape = RoundedCornerShape(8.dp), color = Color(0xFF172636)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("模拟参数", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
                TileGrid(
                    columns = 3,
                    tiles = listOf("normal", "dos", "fuzzy", "spoofing", "mixed").map { scenario ->
                        TileSpec(
                            title = scenario,
                            subtitle = if (state.scenario == scenario) "已选择" else "点击选择",
                            accent = if (state.scenario == scenario) Color(0xFF35D0A5) else Color(0xFF4D6075),
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
            Text("日志", color = Color.White, fontSize = 32.sp, fontWeight = FontWeight.Bold)
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ActionButton("加载最近日志", state.backendReady, Modifier.weight(1f)) { showLogs() }
                ActionButton("系统状态", state.backendReady, Modifier.weight(1f), secondary = true) { showSystemStatus() }
            }
            ResultSurface(state.resultTitle, state.resultBody, Modifier.weight(1f), scrollable = true)
        }
    }

    @Composable
    private fun WebPanel(state: CarUiState) {
        Column(
            modifier = Modifier.fillMaxSize().padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "原 Web 面板",
                    color = Color.White,
                    fontSize = 30.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f)
                )
                ActionButton("返回磁贴", true, Modifier.widthIn(min = 150.dp), secondary = true) {
                    updateUi { it.copy(activePanel = CarPanel.Dashboard) }
                }
                ActionButton("刷新 Web", state.backendReady, Modifier.widthIn(min = 150.dp)) {
                    webView?.reload() ?: loadWebUiIfAvailable()
                }
            }
            Surface(
                modifier = Modifier.fillMaxWidth().weight(1f),
                shape = RoundedCornerShape(8.dp),
                color = Color.Black
            ) {
                AndroidView(
                    modifier = Modifier.fillMaxSize(),
                    factory = { context ->
                        WebView(context).also { view ->
                            webView = view
                            configureWebView(view)
                            if (state.backendReady) view.loadUrl("$backendUrl/ui/")
                        }
                    },
                    update = { view ->
                        if (state.backendReady && view.url.isNullOrBlank()) {
                            view.loadUrl("$backendUrl/ui/")
                        }
                    }
                )
            }
        }
    }

    @Composable
    private fun StatusPill(state: CarUiState) {
        val color = if (state.backendReady) Color(0xFF35D0A5) else Color(0xFFFFC857)
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
        Surface(modifier = modifier.heightIn(min = 98.dp), shape = RoundedCornerShape(8.dp), color = Color(0xFF172636)) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.SpaceBetween
            ) {
                Text(label, color = Color(0xFFB9C8D8), fontSize = 16.sp)
                Text(value, color = accent, fontSize = 34.sp, fontWeight = FontWeight.Bold, maxLines = 1)
            }
        }
    }

    @Composable
    private fun NavButton(label: String, panel: CarPanel, active: CarPanel, modifier: Modifier = Modifier) {
        val selected = panel == active
        Button(
            onClick = {
                updateUi { it.copy(activePanel = panel) }
                if (panel == CarPanel.Web) loadWebUiIfAvailable()
            },
            modifier = modifier.fillMaxWidth().heightIn(min = 64.dp),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = if (selected) Color(0xFF35D0A5) else Color(0xFF26384A),
                contentColor = if (selected) Color(0xFF061915) else Color.White
            )
        ) {
            Text(label, fontSize = 18.sp, fontWeight = FontWeight.Bold)
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
        Button(
            onClick = tile.onClick,
            enabled = tile.enabled,
            modifier = modifier.fillMaxWidth().heightIn(min = 112.dp),
            shape = RoundedCornerShape(8.dp),
            contentPadding = PaddingValues(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = tile.accent.copy(alpha = 0.92f),
                contentColor = Color(0xFF061019),
                disabledContainerColor = Color(0xFF253344),
                disabledContentColor = Color(0xFF8292A3)
            )
        ) {
            Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(tile.title, fontSize = 22.sp, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(tile.subtitle, fontSize = 15.sp, lineHeight = 20.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
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
        val color = when {
            danger -> Color(0xFFFF6B6B)
            secondary -> Color(0xFF4D6075)
            else -> Color(0xFF35D0A5)
        }
        Button(
            onClick = onClick,
            enabled = enabled,
            modifier = modifier.heightIn(min = 68.dp),
            shape = RoundedCornerShape(8.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = color,
                contentColor = if (secondary) Color.White else Color(0xFF061915),
                disabledContainerColor = Color(0xFF253344),
                disabledContentColor = Color(0xFF8292A3)
            )
        ) {
            Text(label, fontSize = 18.sp, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
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
        val contentModifier = if (scrollable) {
            Modifier.padding(16.dp).verticalScroll(rememberScrollState())
        } else {
            Modifier.padding(16.dp)
        }
        Surface(
            modifier = modifier.fillMaxWidth().heightIn(min = 180.dp),
            shape = RoundedCornerShape(8.dp),
            color = Color(0xFF172636)
        ) {
            Column(
                modifier = contentModifier,
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(title, color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
                Text(
                    body,
                    color = Color(0xFFD7E4EF),
                    fontSize = 17.sp,
                    lineHeight = 24.sp,
                    fontFamily = FontFamily.Monospace
                )
            }
        }
    }

    @Composable
    private fun ChatBubble(message: ChatMessage) {
        val isUser = message.role == "user"
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(8.dp),
            color = if (isUser) Color(0xFF214D48) else Color(0xFF172636)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    if (isUser) "分析员" else "AI 助手",
                    color = if (isUser) Color(0xFF35D0A5) else Color(0xFF8AD8FF),
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(message.content, color = Color.White, fontSize = 19.sp, lineHeight = 28.sp)
            }
        }
    }

    class AndroidBridge(private val activity: MainActivity) {
        @JavascriptInterface
        fun pickCaptureFile() {
            activity.runOnUiThread { activity.pickCaptureFile() }
        }
    }
}

private enum class CarPanel {
    Dashboard,
    Assistant,
    Console,
    Logs,
    Web
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

private data class CarUiState(
    val backendStatus: String = "正在启动后端...",
    val backendReady: Boolean = false,
    val relayStatus: String = "Relay: 等待后端启动",
    val relayUrl: String = "http://114.55.164.250:8000",
    val relayKey: String = "",
    val apiKey: String = "",
    val packetCount: String = "0",
    val alertCount: String = "0",
    val resultTitle: String = "等待操作",
    val resultBody: String = "大屏磁贴界面已加载。后端启动完成后，可以直接触控磁贴执行导入、检测、同步和 AI 分析。",
    val activePanel: CarPanel = CarPanel.Dashboard,
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
