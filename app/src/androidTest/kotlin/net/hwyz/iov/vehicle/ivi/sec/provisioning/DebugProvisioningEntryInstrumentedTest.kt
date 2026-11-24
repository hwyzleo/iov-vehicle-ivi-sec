package net.hwyz.iov.vehicle.ivi.sec.provisioning

import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Debug/engineering entry evidence: the provisioning UI is reachable without exporting the production
 * activity. Release builds do not contain this alias.
 */
@RunWith(AndroidJUnit4::class)
class DebugProvisioningEntryInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val aliasName = "${context.packageName}.provisioning.DebugProvisioningEntry"

    @Test
    fun debugEntryIsExportedAndTargetsProvisioningActivity() {
        val info = context.packageManager.getActivityInfo(ComponentName(context.packageName, aliasName), 0)
        assertTrue(info.exported)
        assertEquals(
            "${context.packageName}.provisioning.ProvisioningActivity",
            info.targetActivity,
        )
    }

    @Test
    fun debugEntryHandlesExplicitDebugProvisionAction() {
        val matches = context.packageManager.queryIntentActivities(
            Intent("net.hwyz.iov.vehicle.ivi.sec.action.DEBUG_PROVISION").setPackage(context.packageName),
            PackageManager.MATCH_DEFAULT_ONLY,
        )
        assertTrue(matches.any { it.activityInfo.name == aliasName })
    }
}
