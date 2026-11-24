package net.hwyz.iov.vehicle.ivi.sec

import android.app.Application
import android.content.Context

/** Process wide entry point; the graph is assembled once and shared by the service, provider and UI. */
class IviSecApplication : Application() {

    /** Test seam for unit tests and instrumentation that must not touch production storage. */
    var graphOverride: SecGraph? = null

    val graph: SecGraph
        get() = graphOverride ?: defaultGraph

    private val defaultGraph: SecGraph by lazy { SecGraph(this) }
}

internal fun Context.secGraph(): SecGraph = (applicationContext as IviSecApplication).graph
