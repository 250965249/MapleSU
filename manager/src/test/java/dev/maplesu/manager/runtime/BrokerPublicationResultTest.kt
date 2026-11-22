package dev.maplesu.manager.runtime

import java.util.concurrent.CompletableFuture
import org.junit.Assert.*
import org.junit.Test

class BrokerPublicationResultTest {
    @Test fun onlyAnAcknowledgedBindingIsReady() {
        val pending = CompletableFuture<Unit>()
        assertFalse(brokerPublicationReady(null))
        assertFalse(brokerPublicationReady(pending))
        pending.complete(Unit)
        assertTrue(brokerPublicationReady(pending))
    }

    @Test fun failedOrCancelledBindingCannotBeReusedAsSuccess() {
        val failed = CompletableFuture<Unit>()
        failed.completeExceptionally(IllegalStateException("SU_PUBLICATION_NULL"))
        assertFalse(brokerPublicationReady(failed))
        val cancelled = CompletableFuture<Unit>()
        cancelled.cancel(false)
        assertFalse(brokerPublicationReady(cancelled))
    }
}
