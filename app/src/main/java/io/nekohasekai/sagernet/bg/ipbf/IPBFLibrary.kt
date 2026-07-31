package io.nekohasekai.sagernet.bg.ipbf

import com.sun.jna.Callback
import com.sun.jna.Library
import com.sun.jna.Pointer

interface IPBFLibrary : Library {

    interface LogCallback : Callback {
        fun callback(level: Int, message: String?)
    }

    fun ipbp_set_log_callback(callback: LogCallback)

    fun ipbp_version(): Pointer

    fun ipbp_free_string(ptr: Pointer)

    fun ipbp_load_config(config_path: String): Int

    fun ipbp_start_proxy(config_path: String, target_ip: String, interface_ip: String): Pointer?

    fun ipbp_start_proxy_from_config(config_text: String, target_ip: String): Pointer?

    fun ipbp_stop_proxy(handle: Pointer)
}
