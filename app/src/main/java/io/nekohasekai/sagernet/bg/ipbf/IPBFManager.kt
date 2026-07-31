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
        val libDir = SagerNet.application.applicationInfo.nativeLibraryDir
        val soFile = File(libDir, "libip_bypass_plus_frag.so")

        logBuffer.add("[I] Looking for library at: ${soFile.absolutePath}")
        logBuffer.add("[I] Library exists: ${soFile.exists()}")

        if (!soFile.exists()) {
            logBuffer.add("[E] libip_bypass_plus_frag.so not found in nativeLibraryDir")
            logBuffer.add("[E] nativeLibraryDir contents: ${File(libDir).list()?.joinToString()}")
            Logs.w("IPBF .so not found at ${soFile.absolutePath}")
            return
        }

        try {
            System.load(soFile.absolutePath)
            logBuffer.add("[I] System.load OK")
        } catch (e: UnsatisfiedLinkError) {
            logBuffer.add("[E] System.load failed: ${e.message}")
            Logs.w("IPBF System.load failed", e)
            return
        }

        try {
            library = Native.loadLibrary("ip_bypass_plus_frag", IPBFLibrary::class.java)
            logBuffer.add("[I] Native.loadLibrary OK")
        } catch (e: Exception) {
            logBuffer.add("[E] Native.loadLibrary failed: ${e.message}")
            Logs.w("IPBF Native.load failed", e)
            return
        }

        try {
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
            logBuffer.add("[I] Log callback set")
        } catch (e: Exception) {
            logBuffer.add("[E] Failed to set log callback: ${e.message}")
            Logs.w("IPBF log callback failed", e)
            return
        }

        val ver = getVersion()
        logBuffer.add("[I] IPBF library loaded (v$ver)")
        Logs.i("IPBF library loaded, version: $ver")
    }

    fun start() {
        if (handle != null) return
        val lib = library ?: run {
            logBuffer.add("[E] Library not loaded, call init() first")
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

            val configPath = configFile.absolutePath

            val result = lib.ipbp_load_config(configPath)
            if (result != 0) {
                logBuffer.add("[E] Config validation failed (code: $result)")
                return
            }
            logBuffer.add("[I] Config validated OK")

            handle = lib.ipbp_start_proxy(configPath, "", "")

            if (handle != null) {
                logBuffer.add("[I] IPBF proxy started successfully")
            } else {
                logBuffer.add("[E] ipbp_start_proxy returned NULL")
            }
        } catch (e: Exception) {
            Logs.w("IPBF start failed", e)
            logBuffer.add("[E] Exception: ${e.message}")
            logBuffer.add("[E] ${e.stackTraceToString()}")
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
            "unknown: ${e.message}"
        }
    }
}
