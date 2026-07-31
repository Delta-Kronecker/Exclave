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

            logBuffer.add("[I] Step 2: loading native library via Native.load")
            library = Native.load(soFile.absolutePath, IPBFLibrary::class.java)
            logBuffer.add("[I] Native.load OK")
        } catch (e: UnsatisfiedLinkError) {
            logBuffer.add("[E] UnsatisfiedLinkError: ${e.message}")
            logBuffer.add("[E] This means the .so cannot be loaded. Check ABI match.")
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

            val configPath = configFile.absolutePath

            val result = lib.ipbp_load_config(configPath)
            logBuffer.add("[I] ipbp_load_config result: $result")
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
        } catch (e: Throwable) {
            Logs.w("IPBF start failed", e)
            logBuffer.add("[E] Exception (${e.javaClass.simpleName}): ${e.message}")
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
