package com.maplesu.core.ui.webui

import com.maplesu.core.ui.webui.file.KsuIO
import com.maplesu.core.ui.webui.file.ManagedInputStream
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class WebUiIoLifecycleTest {
    private fun waitFor(message:String, predicate:()->Boolean) {
        val deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(3)
        while(!predicate()) { if(System.nanoTime()>deadline) fail(message);Thread.sleep(2) }
    }

    @Test fun aDisposedPageRejectsLateStreamOpenRequests() {
        val io = KsuIO()
        assertTrue(io.canOpenStream())
        io.destroy()
        assertFalse(io.canOpenStream())
    }

    @Test fun closingOnePageLeavesTheOtherPagesStreamsUsable() {
        val first = KsuIO()
        val second = KsuIO()
        val firstClosed = java.util.concurrent.atomic.AtomicBoolean()
        val secondClosed = java.util.concurrent.atomic.AtomicBoolean()
        first.openInputStreams["first"] = ManagedInputStream(object : ByteArrayInputStream(byteArrayOf(1)) {
            override fun close() { firstClosed.set(true); super.close() }
        })
        second.openInputStreams["second"] = ManagedInputStream(object : ByteArrayInputStream(byteArrayOf(2, 3)) {
            override fun close() { secondClosed.set(true); super.close() }
        })

        first.destroy()
        waitFor("first stream not closed"){firstClosed.get()}
        assertFalse(secondClosed.get())
        assertEquals("", first.FileInputStream().read("second"))
        assertEquals(2, second.FileInputStream().available("second"))
        assertEquals("AgM=", second.FileInputStream().read("second", 2))
        second.destroy()
        waitFor("second stream not closed"){secondClosed.get()}
    }

    @Test fun streamIdsStayScopedToThePageThatOpenedThem() {
        val owner = KsuIO()
        val other = KsuIO()
        val output = ByteArrayOutputStream()
        owner.openOutputStreams["output"] = output
        assertFalse(other.FileOutputStream().write("output", "aGk="))
        assertTrue(owner.FileOutputStream().write("output", "aGk="))
        assertTrue(owner.FileOutputStream().writeByte("output", 10))
        assertTrue(owner.FileOutputStream().flush("output"))
        assertEquals("hi\n", output.toString("UTF-8"))
        assertFalse(other.FileOutputStream().close("output"))
        assertTrue(owner.FileOutputStream().close("output"))
        assertFalse(owner.FileOutputStream().close("output"))
    }

    @Test fun destructionClosesInputAndOutputAndCanBeRepeated() {
        val io = KsuIO()
        val closed = java.util.concurrent.atomic.AtomicInteger()
        io.openInputStreams["input"] = ManagedInputStream(object : ByteArrayInputStream(byteArrayOf(4)) {
            override fun close() { closed.incrementAndGet(); super.close() }
        })
        io.openOutputStreams["output"] = object : ByteArrayOutputStream() {
            override fun close() { closed.incrementAndGet(); super.close() }
        }
        io.destroy()
        io.destroy()
        waitFor("streams not closed"){closed.get()==2}
        assertEquals("", io.FileInputStream().read("input"))
        assertFalse(io.FileOutputStream().writeByte("output", 1))
        assertEquals(0, io.openInputStreams.size)
        assertEquals(0, io.openOutputStreams.size)
    }

    @Test fun readsKeepTheUpstreamChunkLimitAndEofSemantics() {
        val io = KsuIO()
        io.openInputStreams["input"] = ManagedInputStream(ByteArrayInputStream(byteArrayOf(1, 2)))
        assertEquals("AQ==", io.FileInputStream().read("input", 0))
        assertEquals("Ag==", io.FileInputStream().read("input", Int.MAX_VALUE))
        assertEquals("", io.FileInputStream().read("input"))
        assertEquals(0, io.FileInputStream().available("input"))
        io.destroy()
    }

    @Test fun mixedStreamBudgetAndParallelOpenRequestsRespectTheSinglePageLimit() {
        val io = KsuIO()
        val ready = java.util.concurrent.CountDownLatch(1)
        val accepted = java.util.concurrent.atomic.AtomicInteger()
        val calls = (0 until 80).map { index ->
            Thread {
                ready.await()
                runCatching {
                    if (index % 2 == 0) io.openInput { ByteArrayInputStream(byteArrayOf(1)) }
                    else io.openOutput { ByteArrayOutputStream() }
                }.onSuccess { accepted.incrementAndGet() }
            }.apply { start() }
        }
        ready.countDown(); calls.forEach { it.join() }
        assertEquals(50, accepted.get())
        assertEquals(50, io.openInputStreams.size + io.openOutputStreams.size)
        io.destroy()
        waitFor("stream maps not reclaimed"){io.openInputStreams.isEmpty() && io.openOutputStreams.isEmpty()}
    }

    @Test fun destroyingAnOwnerWhileAFactoryRunsClosesTheStreamAndRejectsTheHandle() {
        val io = KsuIO()
        val factoryEntered = java.util.concurrent.CountDownLatch(1)
        val releaseFactory = java.util.concurrent.CountDownLatch(1)
        val closed = java.util.concurrent.atomic.AtomicBoolean()
        val result = java.util.concurrent.atomic.AtomicReference<Result<String>>()
        val opener = Thread {
            result.set(runCatching {
                io.openInput {
                    factoryEntered.countDown(); releaseFactory.await()
                    object : ByteArrayInputStream(byteArrayOf(1)) {
                        override fun close() { closed.set(true); super.close() }
                    }
                }
            })
        }
        val destroyer = Thread { io.destroy() }
        opener.start()
        try {
            assertTrue(factoryEntered.await(3, java.util.concurrent.TimeUnit.SECONDS))
            destroyer.start()
            waitFor("owner did not invalidate the page") { !io.canOpenStream() }
        } finally {
            releaseFactory.countDown()
            opener.join(3000)
            destroyer.join(3000)
        }
        waitFor("late registered stream not closed"){closed.get()}
        assertEquals(0, io.openInputStreams.size)
        assertFalse(io.canOpenStream())
        assertTrue("closed page returned a stream handle", result.get()?.exceptionOrNull() is IllegalStateException)
    }
    @Test fun destroyReturnsAndRejectsNewIoWhileFactoryOwnsTheMonitor() {
        val io=KsuIO();val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1);val returned=java.util.concurrent.CountDownLatch(1)
        val closes=java.util.concurrent.atomic.AtomicInteger()
        val result=java.util.concurrent.atomic.AtomicReference<Result<String>>()
        val opener=Thread { result.set(runCatching { io.openInput { entered.countDown();check(release.await(3,java.util.concurrent.TimeUnit.SECONDS));object:ByteArrayInputStream(byteArrayOf(1)){override fun close(){closes.incrementAndGet();super.close()}} } }) }
        opener.start();assertTrue(entered.await(3,java.util.concurrent.TimeUnit.SECONDS))
        val disposer=Thread {io.destroy();returned.countDown()};disposer.start()
        try {
            assertTrue("destroy waited for blocked stream factory",returned.await(200,java.util.concurrent.TimeUnit.MILLISECONDS))
            assertFalse(io.canOpenStream());assertEquals("",io.FileInputStream().read("late"))
        } finally {release.countDown();opener.join(3000);disposer.join(3000)}
        waitFor("late factory resource not reclaimed once"){closes.get()==1};assertTrue(io.openInputStreams.isEmpty())
        assertTrue(result.get()?.exceptionOrNull() is IllegalStateException)
    }
    @Test fun closingThePageDuringOutputCreationRejectsTheHandleAndClosesTheStream() {
        val io = KsuIO()
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val closes = java.util.concurrent.atomic.AtomicInteger()
        val result = java.util.concurrent.atomic.AtomicReference<Result<String>>()
        val opener = Thread {
            result.set(runCatching {
                io.openOutput {
                    entered.countDown()
                    check(release.await(3, java.util.concurrent.TimeUnit.SECONDS))
                    object : ByteArrayOutputStream() {
                        override fun close() { closes.incrementAndGet(); super.close() }
                    }
                }
            })
        }
        opener.start()
        try {
            assertTrue(entered.await(3, java.util.concurrent.TimeUnit.SECONDS))
            io.destroy()
        } finally {
            release.countDown()
            opener.join(3000)
        }
        assertTrue("closed page returned an output handle", result.get()?.exceptionOrNull() is IllegalStateException)
        waitFor("late output stream not closed once") { closes.get() == 1 }
        assertTrue(io.openOutputStreams.isEmpty())
    }

    @Test fun destroyedIoRejectsReadsAndWritesWhileBackgroundCloseIsBlocked() {
        val io=KsuIO();val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1);val returned=java.util.concurrent.CountDownLatch(1)
        val closes=java.util.concurrent.atomic.AtomicInteger()
        io.openInputStreams["input"]=ManagedInputStream(ByteArrayInputStream(byteArrayOf(1)))
        io.openOutputStreams["output"]=object:ByteArrayOutputStream(){override fun close(){entered.countDown();check(release.await(3,java.util.concurrent.TimeUnit.SECONDS));closes.incrementAndGet();super.close()}}
        val disposer=Thread {io.destroy();io.destroy();returned.countDown()};disposer.start()
        try {
            assertTrue(entered.await(3,java.util.concurrent.TimeUnit.SECONDS));assertTrue("destroy waited for output close",returned.await(200,java.util.concurrent.TimeUnit.MILLISECONDS))
            assertEquals("",io.FileInputStream().read("input"));assertFalse(io.FileOutputStream().writeByte("output",1))
        } finally {release.countDown();disposer.join(3000)}
        waitFor("output resource not reclaimed once"){closes.get()==1}
    }
    @Test fun destroyDoesNotWaitForInFlightWhileOpenAction() {
        val io=KsuIO();val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1);val returned=java.util.concurrent.CountDownLatch(1)
        val worker=Thread {io.whileOpen{entered.countDown();check(release.await(3,java.util.concurrent.TimeUnit.SECONDS))}};worker.start();assertTrue(entered.await(3,java.util.concurrent.TimeUnit.SECONDS))
        val disposer=Thread {io.destroy();returned.countDown()};disposer.start()
        try {assertTrue("destroy waited for whileOpen IO",returned.await(200,java.util.concurrent.TimeUnit.MILLISECONDS));assertFalse(io.canOpenStream())}
        finally {release.countDown();worker.join(3000);disposer.join(3000)}
        assertThrows(IllegalStateException::class.java){io.whileOpen{fail("closed owner accepted action")}}
    }

    @Test fun retainedFileFacadesRejectIoAfterOwnerDestruction() {
        val owner=KsuIO();val facade=owner.File("/fixture/old");val calls=java.util.concurrent.atomic.AtomicInteger()
        val file=object:com.topjohnwu.superuser.io.SuFile("/fixture/old") {
            override fun exists():Boolean {calls.incrementAndGet();return true}
            override fun createNewFile():Boolean {calls.incrementAndGet();return true}
            override fun delete():Boolean {calls.incrementAndGet();return true}
            override fun clear():Boolean {calls.incrementAndGet();return true}
            override fun setReadable(readable:Boolean,ownerOnly:Boolean):Boolean {calls.incrementAndGet();return true}
        }
        val field=facade.javaClass.getDeclaredField("suFile").apply{isAccessible=true};field.set(facade,file)
        assertTrue(facade.exists());owner.destroy()
        assertFalse(facade.exists());assertFalse(facade.createNewFile());assertFalse(facade.delete());assertFalse(facade.clear());assertFalse(facade.setReadable(true,true))
        val late=owner.File("/fixture/late");field.set(late,file);assertFalse(late.delete())
        assertEquals(1,calls.get())
    }
    @Test fun queuedFactoryDoesNotRunAfterOwnerInvalidation() {
        val owner=KsuIO();val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1);val returned=java.util.concurrent.CountDownLatch(1);val factories=java.util.concurrent.atomic.AtomicInteger()
        val holder=Thread{owner.whileOpen{entered.countDown();check(release.await(3,java.util.concurrent.TimeUnit.SECONDS))}};holder.start();assertTrue(entered.await(3,java.util.concurrent.TimeUnit.SECONDS))
        val opener=Thread{runCatching{owner.openInput{factories.incrementAndGet();ByteArrayInputStream(byteArrayOf(1))}}};opener.start();waitFor("opener did not queue"){opener.state==Thread.State.BLOCKED}
        val disposer=Thread{owner.destroy();returned.countDown()};disposer.start()
        try {assertTrue("destroy waited for queued factory monitor",returned.await(200,java.util.concurrent.TimeUnit.MILLISECONDS))}
        finally {release.countDown();holder.join(3000);opener.join(3000);disposer.join(3000)}
        assertEquals(0,factories.get())
    }
    @Test fun randomAccessCleanupClaimsResourceBeforeClosingIt() {
        val owner=KsuIO();val entered=java.util.concurrent.CountDownLatch(1);val release=java.util.concurrent.CountDownLatch(1);val closes=java.util.concurrent.atomic.AtomicInteger()
        val file=object:com.topjohnwu.superuser.io.SuRandomAccessFile(), java.io.DataInput by java.io.DataInputStream(ByteArrayInputStream(byteArrayOf())), java.io.DataOutput by java.io.DataOutputStream(ByteArrayOutputStream()) {
            override fun read()=-1
            override fun read(bytes:ByteArray)=-1
            override fun read(bytes:ByteArray,offset:Int,length:Int)=-1
            override fun seek(offset:Long){}
            override fun setLength(length:Long){}
            override fun length()=0L
            override fun getFilePointer()=0L
            override fun close(){entered.countDown();check(release.await(3,java.util.concurrent.TimeUnit.SECONDS));closes.incrementAndGet()}
        }
        val facade=owner.RandomAccessFile();val field=facade.javaClass.getDeclaredField("openFiles").apply{isAccessible=true}
        @Suppress("UNCHECKED_CAST") val files=field.get(facade) as java.util.concurrent.ConcurrentHashMap<String,com.topjohnwu.superuser.io.SuRandomAccessFile>;files["file"]=file
        val disposer=Thread{owner.destroy()};disposer.start();assertTrue(entered.await(3,java.util.concurrent.TimeUnit.SECONDS))
        val result=java.util.concurrent.atomic.AtomicReference<Boolean?>();val closer=Thread{result.set(facade.close("file"))};closer.start()
        try {closer.join(200);assertEquals("resource still visible while cleanup owns it",false,result.get())}
        finally {release.countDown();disposer.join(3000);closer.join(3000)}
        waitFor("random access file not closed"){closes.get()>0};assertEquals(1,closes.get())
    }

    @Test fun retiredPageRejectsRetainedHandlesBeforeDestroyWithoutAffectingAnotherPage() {
        val current = java.util.concurrent.atomic.AtomicBoolean(true)
        val closes = java.util.concurrent.atomic.AtomicInteger()
        val owner = KsuIO(pageCurrent = current::get)
        val other = KsuIO()
        val output = object : ByteArrayOutputStream() {
            override fun close() { closes.incrementAndGet(); super.close() }
        }
        val inputId = owner.openInput {
            object : ByteArrayInputStream(byteArrayOf(1, 2)) {
                override fun close() { closes.incrementAndGet(); super.close() }
            }
        }
        val outputId = owner.openOutput { output }
        val otherInput = other.openInput { ByteArrayInputStream(byteArrayOf(9)) }
        val otherOutput = ByteArrayOutputStream()
        val otherOutputId = other.openOutput { otherOutput }
        val heldInput = owner.FileInputStream()
        val heldOutput = owner.FileOutputStream()
        try {
            assertTrue(heldOutput.writeByte(outputId, 7))
            assertTrue(heldOutput.flush(outputId))
            current.set(false)

            assertFalse(owner.canOpenStream())
            assertEquals("", heldInput.read(inputId))
            assertEquals(0, heldInput.available(inputId))
            assertFalse(heldOutput.writeByte(outputId, 8))
            assertFalse(heldOutput.flush(outputId))
            assertArrayEquals(byteArrayOf(7), output.toByteArray())
            assertEquals("Page retirement should precede resource cleanup", 0, closes.get())
            assertEquals(1, owner.openInputStreams.size)
            assertEquals(1, owner.openOutputStreams.size)
            assertEquals("CQ==", other.FileInputStream().read(otherInput))
            assertTrue(other.FileOutputStream().writeByte(otherOutputId, 10))
            assertTrue(other.FileOutputStream().flush(otherOutputId))
            assertArrayEquals(byteArrayOf(10), otherOutput.toByteArray())
        } finally {
            owner.destroy()
            other.destroy()
        }
        waitFor("Retired page resources were not closed exactly once") { closes.get() == 2 }
    }

    @Test fun retiredPageClosesAnInFlightInputWithoutReturningItsHandle() {
        assertPageRetirementDuringFactory(input = true)
    }

    @Test fun retiredPageClosesAnInFlightOutputWithoutReturningItsHandle() {
        assertPageRetirementDuringFactory(input = false)
    }

    private fun assertPageRetirementDuringFactory(input: Boolean) {
        val current = java.util.concurrent.atomic.AtomicBoolean(true)
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val closes = java.util.concurrent.atomic.AtomicInteger()
        val result = java.util.concurrent.atomic.AtomicReference<Result<String>>()
        val owner = KsuIO(pageCurrent = current::get)
        val opener = Thread {
            result.set(runCatching {
                if (input) owner.openInput {
                    entered.countDown()
                    check(release.await(3, java.util.concurrent.TimeUnit.SECONDS))
                    object : ByteArrayInputStream(byteArrayOf(1)) {
                        override fun close() { closes.incrementAndGet(); super.close() }
                    }
                } else owner.openOutput {
                    entered.countDown()
                    check(release.await(3, java.util.concurrent.TimeUnit.SECONDS))
                    object : ByteArrayOutputStream() {
                        override fun close() { closes.incrementAndGet(); super.close() }
                    }
                }
            })
        }
        opener.start()
        try {
            assertTrue(entered.await(3, java.util.concurrent.TimeUnit.SECONDS))
            current.set(false)
            assertFalse(owner.canOpenStream())
            release.countDown()
            opener.join(3000)

            assertFalse("Stream factory did not finish", opener.isAlive)
            assertTrue("Retired page returned a stream handle",
                result.get()?.exceptionOrNull() is IllegalStateException)
            assertEquals(1, closes.get())
            assertTrue(owner.openInputStreams.isEmpty())
            assertTrue(owner.openOutputStreams.isEmpty())
        } finally {
            release.countDown()
            opener.join(3000)
            owner.destroy()
        }
    }

    @Test fun retiredPageRejectsItsInjectedShellFactoryBeforeDestroy() {
        val current = java.util.concurrent.atomic.AtomicBoolean(true)
        val opens = java.util.concurrent.atomic.AtomicInteger()
        val shell = PageCurrentMockShell()
        val owner = KsuIO(shellFactory = { opens.incrementAndGet(); shell }, pageCurrent = current::get)
        val facade = owner.File("/fixture/retired")
        try {
            current.set(false)

            assertFalse(facade.exists())
            assertFalse(facade.delete())
            assertEquals("", owner.FileInputStream().open("/fixture/retired"))
            assertEquals("", owner.FileOutputStream().open("/fixture/retired"))
            assertEquals("", owner.RandomAccessFile().open("/fixture/retired", "r"))
            assertThrows(IllegalStateException::class.java) { owner.file("/fixture/retired") }
            assertEquals(0, opens.get())
            assertEquals(0, shell.closes.get())
        } finally {
            owner.destroy()
        }
    }

    @Test fun retiredPageClosesAnInFlightInjectedShellWithoutReturningAFile() {
        val current = java.util.concurrent.atomic.AtomicBoolean(true)
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val opens = java.util.concurrent.atomic.AtomicInteger()
        val shell = PageCurrentMockShell()
        val result = java.util.concurrent.atomic.AtomicReference<Result<com.topjohnwu.superuser.io.SuFile>>()
        val owner = KsuIO(shellFactory = {
            opens.incrementAndGet()
            entered.countDown()
            check(release.await(3, java.util.concurrent.TimeUnit.SECONDS))
            shell
        }, pageCurrent = current::get)
        val opener = Thread { result.set(runCatching { owner.file("/fixture/in-flight") }) }
        opener.start()
        try {
            assertTrue(entered.await(3, java.util.concurrent.TimeUnit.SECONDS))
            current.set(false)
            release.countDown()
            opener.join(3000)

            assertFalse("Injected shell factory did not finish", opener.isAlive)
            val failure = result.get()?.exceptionOrNull()
            assertTrue(failure is java.util.concurrent.ExecutionException)
            assertTrue(failure?.cause is IllegalStateException)
            assertEquals(1, opens.get())
            assertEquals(1, shell.closes.get())
            assertThrows(IllegalStateException::class.java) { owner.file("/fixture/late") }
            assertEquals(1, opens.get())
        } finally {
            release.countDown()
            opener.join(3000)
            owner.destroy()
        }
    }

    private class PageCurrentMockShell : com.topjohnwu.superuser.Shell() {
        val closes = java.util.concurrent.atomic.AtomicInteger()
        override fun isAlive() = closes.get() == 0
        override fun getStatus() = NON_ROOT_SHELL
        override fun close() { closes.incrementAndGet() }
        override fun waitAndClose(timeout: Long, unit: java.util.concurrent.TimeUnit): Boolean {
            close()
            return true
        }
        override fun execTask(task: Task) = error("Unexpected mock shell task")
        override fun submitTask(task: Task) = error("Unexpected mock shell task")
        override fun newJob(): Job = error("Unexpected mock shell command")
    }

}
