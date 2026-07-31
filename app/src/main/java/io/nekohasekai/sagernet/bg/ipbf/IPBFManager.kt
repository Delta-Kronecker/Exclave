package io.nekohasekai.sagernet.bg.ipbf

import com.sun.jna.Native
import com.sun.jna.Pointer
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.ktx.Logs
import java.io.File
import java.util.concurrent.ConcurrentLinkedQueue

object IPBFManager {

    private var library: IPBFLibrary? = null
    private var handle: Pointer? = null
    private val logBuffer = ConcurrentLinkedQueue<String>()
    private const val MAX_LOG_LINES = 2000

    val isRunning: Boolean get() = handle != null

    fun init() {
        try {
            logBuffer.add("[I] Step 1: locating .so file")
            val libDir = SagerNet.application.applicationInfo.nativeLibraryDir
            val soFile = File(libDir, "libip_bypass_plus_frag.so")
            logBuffer.add("[I] nativeLibraryDir: $libDir")
            logBuffer.add("[I] .so exists: ${soFile.exists()}")

            if (!soFile.exists()) {
                val files = File(libDir).list()
                logBuffer.add("[E] .so NOT found. Dir contents: ${files?.joinToString()}")
                return
            }

            logBuffer.add("[I] Step 2: loading native library")
            library = Native.load(soFile.absolutePath, IPBFLibrary::class.java)
            logBuffer.add("[I] Native.load OK")
        } catch (e: UnsatisfiedLinkError) {
            logBuffer.add("[E] UnsatisfiedLinkError: ${e.message}")
            Logs.w("IPBF load error", e)
            return
        } catch (e: Throwable) {
            logBuffer.add("[E] Load failed (${e.javaClass.simpleName}): ${e.message}")
            Logs.w("IPBF load error", e)
            return
        }

        try {
            logBuffer.add("[I] Step 3: setting log callback")
            library!!.ipbp_set_log_callback(object : IPBFLibrary.LogCallback {
                override fun callback(level: Int, message: String?) {
                    if (message != null) {
                        val prefix = when (level) {
                            0 -> "I"
                            1 -> "E"
                            2 -> "W"
                            else -> "D"
                        }
                        val line = "[$prefix] $message"
                        logBuffer.add(line)
                        Logs.i("IPBF: $line")
                        while (logBuffer.size > MAX_LOG_LINES) {
                            logBuffer.poll()
                        }
                    }
                }
            })
            logBuffer.add("[I] Step 3 OK: log callback set")
        } catch (e: Throwable) {
            logBuffer.add("[E] Step 3 failed: ${e.message}")
            Logs.w("IPBF log callback failed", e)
            return
        }

        try {
            logBuffer.add("[I] Step 4: getting version")
            val ver = getVersion()
            logBuffer.add("[I] Step 4 OK: IPBF loaded (v$ver)")
            Logs.i("IPBF library loaded, version: $ver")
        } catch (e: Throwable) {
            logBuffer.add("[E] Step 4 failed: ${e.message}")
        }

        try {
            logBuffer.add("[I] Step 5: copying assets to internal storage")
            copyAssetsIfNeeded()
            val ipbfDir = File(SagerNet.deviceStorage.noBackupFilesDir, "ipbf")
            logBuffer.add("[I] Step 5 OK: ipbf dir = ${ipbfDir.absolutePath}")
            logBuffer.add("[I] config.toml exists: ${File(ipbfDir, "config.toml").exists()}")
            logBuffer.add("[I] ip_list.txt exists: ${File(ipbfDir, "ip_list.txt").exists()}")
        } catch (e: Throwable) {
            logBuffer.add("[E] Step 5 failed (${e.javaClass.simpleName}): ${e.message}")
            Logs.w("IPBF copyAssets failed", e)
        }
    }

    fun start() {
        if (handle != null) return
        val lib = library ?: run {
            logBuffer.add("[E] Library not loaded. init() may have failed.")
            return
        }

        try {
            val ipbfDir = File(SagerNet.deviceStorage.noBackupFilesDir, "ipbf")
            val configFile = File(ipbfDir, "config.toml")

            if (!configFile.exists()) {
                logBuffer.add("[E] config.toml not found at: ${configFile.absolutePath}")
                return
            }

            logBuffer.add("[I] Starting IPBF...")
            logBuffer.add("[I] Config: ${configFile.absolutePath}")

            val configText = buildConfigWithAbsolutePaths(ipbfDir)
            logBuffer.add("[I] Config text length: ${configText.length}")
            logBuffer.add("[I] Config content:\n$configText")

            handle = lib.ipbp_start_proxy_from_config(configText, "104.16.0.1")

            if (handle != null) {
                logBuffer.add("[I] IPBF proxy started successfully")
            } else {
                logBuffer.add("[E] ipbp_start_proxy_from_config returned NULL")
                logBuffer.add("[I] Trying ipbp_start_proxy with file path...")
                val result = lib.ipbp_load_config(configFile.absolutePath)
                logBuffer.add("[I] ipbp_load_config result: $result")
                handle = lib.ipbp_start_proxy(configFile.absolutePath, "104.16.0.1", "127.0.0.1")
                if (handle != null) {
                    logBuffer.add("[I] ipbp_start_proxy succeeded")
                } else {
                    logBuffer.add("[E] ipbp_start_proxy also returned NULL")
                }
            }
        } catch (e: Throwable) {
            Logs.w("IPBF start failed", e)
            logBuffer.add("[E] Exception (${e.javaClass.simpleName}): ${e.message}")
            logBuffer.add("[E] ${e.stackTraceToString()}")
        }
    }

    private fun buildConfigWithAbsolutePaths(ipbfDir: File): String {
        val ipListPath = File(ipbfDir, "ip_list.txt").absolutePath
        return """
MODE = "ip_bypass_plus"
NO_TUI = true
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 40443
IP_POOL = 10
MAX_IP_SCAN = 1000
AUTO_SELECT = false
BYPASS_METHOD = "tls_frag"
IP_LIST = "$ipListPath"
SCAN_TIMEOUT_SECS = 5
RESCAN_INTERVAL_SECS = 0
SNI_SWITCH_MIN_SCORE = 1
IP_MAX_P1_CONCURRENT = 128
IP_MAX_P2_CONCURRENT = 32
SCAN_DOWNLOAD_CAP = 10240
SCAN_UPLOAD_CAP = 10240
SCAN_UPLOAD_PATH = "/"
IP_SCAN_SNI = "cloudflare.com"
TCP_LATENCY_CAP_MS = 500.0
TLS_LATENCY_CAP_MS = 1000.0
TTFB_CAP_MS = 2000.0
SPEED_CAP_BPS = 2048000.0
UPLOAD_SPEED_CAP_BPS = 2048000.0
BYPASS_TIMEOUT_SECS = 20
RELAY_MAX_LIFETIME_SECS = 0
TLS_FRAG_PACKETS = "1-3"
TLS_FRAG_LENGTH = "100-200"
TLS_FRAG_INTERVAL_MS = "10-20"
TCP_SEG_SIZE = 1
TCP_SEG_NODELAY = true
        """.trimIndent()
    }

    fun stop() {
        val lib = library ?: return
        val h = handle ?: return

        try {
            lib.ipbp_stop_proxy(h)
            handle = null
            logBuffer.add("[I] IPBF proxy stopped")
        } catch (e: Throwable) {
            Logs.w("IPBF stop failed", e)
            logBuffer.add("[E] Stop failed: ${e.message}")
            handle = null
        }
    }

    fun setCidrRange(cidr: String) {
        val ipbfDir = File(SagerNet.deviceStorage.noBackupFilesDir, "ipbf")
        val ipList = File(ipbfDir, "ip_list.txt")
        ipList.writeText(cidr.trim() + "\n")
        logBuffer.add("[I] IP range set to: $cidr")
    }

    fun getCidrRange(): String {
        val ipbfDir = File(SagerNet.deviceStorage.noBackupFilesDir, "ipbf")
        val ipList = File(ipbfDir, "ip_list.txt")
        return if (ipList.exists()) ipList.readText().trim().lines().firstOrNull() ?: "" else ""
    }

    fun getLogBuffer(): ConcurrentLinkedQueue<String> = logBuffer

    private fun copyAssetsIfNeeded() {
        val ipbfDir = File(SagerNet.deviceStorage.noBackupFilesDir, "ipbf")
        if (!ipbfDir.exists()) ipbfDir.mkdirs()

        val configToml = File(ipbfDir, "config.toml")
        SagerNet.application.assets.open("ipbf/config.toml").use { input ->
            configToml.outputStream().use { output -> input.copyTo(output) }
        }

        val ipList = File(ipbfDir, "ip_list.txt")
        SagerNet.application.assets.open("ipbf/ip_list.txt").use { input ->
            ipList.outputStream().use { output -> input.copyTo(output) }
        }
    }

    private fun getVersion(): String {
        val lib = library ?: return "unknown"
        return try {
            val ptr = lib.ipbp_version()
            val version = ptr.getString(0)
            lib.ipbp_free_string(ptr)
            version
        } catch (e: Throwable) {
            "unknown: ${e.message}"
        }
    }
}
