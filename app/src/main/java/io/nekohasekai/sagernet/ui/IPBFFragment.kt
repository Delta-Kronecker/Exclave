package io.nekohasekai.sagernet.ui

import android.os.Bundle
import android.view.*
import androidx.appcompat.widget.Toolbar
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.ipbf.IPBFManager
import io.nekohasekai.sagernet.databinding.LayoutIpbfBinding
import androidx.lifecycle.lifecycleScope
import io.nekohasekai.sagernet.ktx.*
import kotlinx.coroutines.*

class IPBFFragment : ToolbarFragment(R.layout.layout_ipbf),
    Toolbar.OnMenuItemClickListener {

    lateinit var binding: LayoutIpbfBinding
    private var logJob: Job? = null

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
            if (cidr.isNotEmpty()) {
                IPBFManager.setCidrRange(cidr)
                if (IPBFManager.isRunning) {
                    IPBFManager.stop()
                    IPBFManager.start()
                }
                updateStatus()
                snackbar(R.string.ipbf_range_applied).show()
            }
        }

        startLogPolling()
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

    private fun startLogPolling() {
        logJob = viewLifecycleOwner.lifecycleScope.launch {
            while (isActive) {
                val logs = IPBFManager.getLogBuffer()
                if (logs.isNotEmpty()) {
                    binding.ipbfLogsText.text = logs.joinToString("\n")
                    binding.ipbfLogsScroll.post {
                        binding.ipbfLogsScroll.fullScroll(View.FOCUS_DOWN)
                    }
                }
                delay(500)
            }
        }
    }

    override fun onDestroy() {
        logJob?.cancel()
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
