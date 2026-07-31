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
            System.loadLibrary("ip_bypass_plus_frag")
            library = Native.load("ip_bypass_plus_frag", IPBFLibrary::class.java)
            library!!.ipbp_set_log_callback(object : IPBFLibrary.LogCallback {
                override fun callback(level: Int, message: String?) {
                    if (message != null) {
                        val prefix = when (level) {
                            0 -> "I"
                            1 -> "E"
                            2 -> "W"
                            else -> "D"
                        }
                        logBuffer.add("[$prefix] $message")
                        while (logBuffer.size > MAX_LOG_LINES) {
                            logBuffer.poll()
                        }
                    }
                }
            })
            copyAssetsIfNeeded()
            Logs.i("IPBF library loaded, version: ${getVersion()}")
            logBuffer.add("[I] IPBF library loaded")
        } catch (e: Exception) {
            Logs.w("Failed to load IPBF library", e)
            logBuffer.add("[E] Failed to load library: ${e.message}")
        }
    }

    private fun copyAssetsIfNeeded() {
        val ipbfDir = File(SagerNet.deviceStorage.noBackupFilesDir, "ipbf")
        if (!ipbfDir.exists()) ipbfDir.mkdirs()

        val configToml = File(ipbfDir, "config.toml")
        if (!configToml.exists()) {
            SagerNet.application.assets.open("ipbf/config.toml").use { input ->
                configToml.outputStream().use { output -> input.copyTo(output) }
            }
        }

        val ipList = File(ipbfDir, "ip_list.txt")
        if (!ipList.exists()) {
            SagerNet.application.assets.open("ipbf/ip_list.txt").use { input ->
                ipList.outputStream().use { output -> input.copyTo(output) }
            }
        }
    }

    fun start() {
        if (handle != null) return
        val lib = library ?: run {
            logBuffer.add("[E] Library not loaded")
            return
        }

        try {
            val ipbfDir = File(SagerNet.deviceStorage.noBackupFilesDir, "ipbf")
            val configToml = File(ipbfDir, "config.toml")
            val configText = configToml.readText()

            logBuffer.clear()
            logBuffer.add("[I] Starting IPBF proxy...")
            handle = lib.ipbp_start_proxy_from_config(configText, "")
            if (handle != null) {
                logBuffer.add("[I] IPBF proxy started")
            } else {
                logBuffer.add("[E] Failed to start IPBF proxy")
            }
        } catch (e: Exception) {
            Logs.w("IPBF start failed", e)
            logBuffer.add("[E] Start failed: ${e.message}")
        }
    }

    fun stop() {
        val lib = library ?: return
        val h = handle ?: return

        try {
            lib.ipbp_stop_proxy(h)
            handle = null
            logBuffer.add("[I] IPBF proxy stopped")
        } catch (e: Exception) {
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

    private fun getVersion(): String {
        val lib = library ?: return "unknown"
        return try {
            val ptr = lib.ipbp_version()
            val version = ptr.getString(0)
            lib.ipbp_free_string(ptr)
            version
        } catch (e: Exception) {
            "unknown"
        }
    }
}
