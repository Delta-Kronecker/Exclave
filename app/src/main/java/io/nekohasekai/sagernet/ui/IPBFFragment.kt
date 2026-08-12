package io.nekohasekai.sagernet.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.*
import android.widget.Toast
import androidx.appcompat.widget.Toolbar
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.ipbf.IPBFManager
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.databinding.LayoutIpbfBinding
import io.nekohasekai.sagernet.ktx.*

class IPBFFragment : ToolbarFragment(R.layout.layout_ipbf),
    Toolbar.OnMenuItemClickListener {

    lateinit var binding: LayoutIpbfBinding
    private val handler = Handler(Looper.getMainLooper())
    private val logRunnable = object : Runnable {
        override fun run() {
            if (isAdded && ::binding.isInitialized && binding.ipbfLogsContainer.visibility == View.VISIBLE) {
                updateLogs()
            }
            handler.postDelayed(this, 500)
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding = LayoutIpbfBinding.bind(view)
        toolbar.setTitle(R.string.ipbf)
        toolbar.inflateMenu(R.menu.ipbf_menu)
        toolbar.setOnMenuItemClickListener(this)

        ViewCompat.setOnApplyWindowInsetsListener(view.findViewById(R.id.ipbf_logs_scroll)) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars()
                        or WindowInsetsCompat.Type.displayCutout()
            )
            v.updatePadding(
                left = bars.left + dp2px(8),
                right = bars.right + dp2px(8),
                bottom = bars.bottom + dp2px(64),
            )
            insets
        }

        (requireActivity() as? MainActivity)?.onBackPressedCallback?.isEnabled = true

        updateStatus()
        binding.ipbfCidrInput.setText(IPBFManager.getCidrRange())
        binding.ipbfFragPackets.setText(DataStore.ipbfTlsFragPackets)
        binding.ipbfFragLength.setText(DataStore.ipbfTlsFragLength)
        binding.ipbfFragInterval.setText(DataStore.ipbfTlsFragInterval)
        binding.ipbfTcpSegSize.setText(DataStore.ipbfTcpSegSize)

        binding.ipbfToggle.setOnClickListener {
            if (IPBFManager.isRunning) {
                IPBFManager.stop()
            } else {
                IPBFManager.start()
            }
            updateStatus()
        }

        binding.ipbfApply.setOnClickListener {
            val cidr = binding.ipbfCidrInput.text?.toString()?.trim() ?: ""
            DataStore.ipbfTlsFragPackets = binding.ipbfFragPackets.text?.toString()?.trim()?.ifEmpty { "1-3" } ?: "1-3"
            DataStore.ipbfTlsFragLength = binding.ipbfFragLength.text?.toString()?.trim()?.ifEmpty { "5-40" } ?: "5-40"
            DataStore.ipbfTlsFragInterval = binding.ipbfFragInterval.text?.toString()?.trim()?.ifEmpty { "1" } ?: "1"
            DataStore.ipbfTcpSegSize = binding.ipbfTcpSegSize.text?.toString()?.trim()?.ifEmpty { "1" } ?: "1"
            if (cidr.isNotEmpty()) {
                IPBFManager.setCidrRange(cidr)
            }
            if (IPBFManager.isRunning) {
                IPBFManager.stop()
                IPBFManager.start()
            }
            updateStatus()
            snackbar(R.string.ipbf_settings_applied).show()
        }

        binding.ipbfToggleLogs.setOnClickListener {
            val show = binding.ipbfLogsContainer.visibility != View.VISIBLE
            binding.ipbfLogsContainer.visibility = if (show) View.VISIBLE else View.GONE
            binding.ipbfToggleLogs.text = getString(if (show) R.string.ipbf_hide_logs else R.string.ipbf_show_logs)
            if (show) updateLogs()
        }

        binding.ipbfCopyLog.setOnClickListener {
            val logs = IPBFManager.getLogBuffer().joinToString("\n")
            if (logs.isNotEmpty()) {
                val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("IPBF Logs", logs)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(requireContext(), R.string.log_copied, Toast.LENGTH_SHORT).show()
            }
        }

        updateLogs()
    }

    override fun onResume() {
        super.onResume()
        handler.post(logRunnable)
    }

    override fun onPause() {
        handler.removeCallbacks(logRunnable)
        super.onPause()
    }

    private fun updateStatus() {
        if (IPBFManager.isRunning) {
            binding.ipbfStatus.text = getString(R.string.ipbf_running)
            binding.ipbfStatus.setTextColor(requireContext().getColour(R.color.material_green_500))
            binding.ipbfToggle.text = getString(R.string.ipbf_stop)
        } else {
            binding.ipbfStatus.text = getString(R.string.ipbf_stopped)
            binding.ipbfStatus.setTextColor(requireContext().getColour(R.color.material_red_500))
            binding.ipbfToggle.text = getString(R.string.ipbf_start)
        }
    }

    private fun updateLogs() {
        val logs = IPBFManager.getLogBuffer()
        if (logs.isNotEmpty()) {
            binding.ipbfLogsText.text = logs.joinToString("\n")
            binding.ipbfLogsScroll.post {
                if (!binding.ipbfCidrInput.hasFocus()) {
                    binding.ipbfLogsScroll.getChildAt(0)?.let {
                        binding.ipbfLogsScroll.scrollTo(0, it.height)
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        handler.removeCallbacks(logRunnable)
        super.onDestroy()
    }

    override fun onMenuItemClick(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_clear_ipbf_log -> {
                IPBFManager.getLogBuffer().clear()
                binding.ipbfLogsText.text = ""
            }
        }
        return true
    }
}
