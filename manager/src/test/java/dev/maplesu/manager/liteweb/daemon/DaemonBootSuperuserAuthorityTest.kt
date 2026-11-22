package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.runtime.authorization.*
import org.junit.Assert.*
import org.junit.Test

class DaemonBootSuperuserAuthorityTest {
    private val uid = 10123
    private val pkg = "com.example.host"
    private val identity = ApplicationIdentity(uid, pkg, listOf(pkg), setOf("a".repeat(64)),
        1000L, 2000L, "/data/app/host/base.apk")

    @Test fun webWritesTheAuthorityBeforeMirroringAndKeepsCommittedRevocationOnFailure() {
        val calls = mutableListOf<String>()
        var state = AuthorizationSnapshot(true, mapOf(uid to identity), rev = 1)
        val authority = DaemonBootSuperuserAuthority(
            execute = { op, _ ->
                calls += op
                when (op) {
                    "snapshot" -> "wire=${SuperuserWire.encode(state)}"
                    "revoke" -> { state = AuthorizationSnapshot(true, emptyMap(), rev = 2); "rev=2" }
                    "mark-applied" -> "rev=2 pending=1"
                    else -> error(op)
                }
            },
            identityOf = { identity }, uidOfPackage = { uid },
            mirror = object : SuperuserMirror {
                override val backend = UltraAllowlistMirror.BACKEND
                override fun apply(snapshot: AuthorizationSnapshot): MirrorOutcome {
                    calls += "mirror"
                    assertTrue(snapshot.grants.isEmpty())
                    return MirrorOutcome.failure("SDK_BUSY")
                }
            },
        )
        assertFalse(authority.setAllowed(pkg, false))
        assertTrue(state.grants.isEmpty())
        assertEquals(listOf("revoke", "snapshot", "mirror", "mark-applied"), calls)
    }

    @Test fun webReadsOnlyLiveIdentityDecisionsFromTheAuthority() {
        var state = AuthorizationSnapshot(true, mapOf(uid to identity), rev = 1)
        val authority = DaemonBootSuperuserAuthority(
            execute = { _, _ -> "wire=${SuperuserWire.encode(state)}" },
            identityOf = { identity }, uidOfPackage = { uid }, mirror = NoSuperuserMirror,
        )
        assertEquals(setOf(pkg), authority.packages())
        state = state.copy(enabled = false)
        assertEquals(emptySet<String>(), authority.packages())
        state = AuthorizationSnapshot.unreadable()
        assertNull(authority.packages())
    }

    @Test fun uninstalledHostIsRevokedUsingTheAuthorityUid() {
        var state = AuthorizationSnapshot(true, mapOf(uid to identity), rev = 1)
        val authority = DaemonBootSuperuserAuthority(
            execute = { op, args -> when (op) {
                "snapshot" -> "wire=${SuperuserWire.encode(state)}"
                "revoke" -> {
                    assertEquals(listOf(uid.toString()), args)
                    state = state.copy(grants = emptyMap(), rev = 2)
                    "rev=2"
                }
                "mark-applied" -> "rev=2 pending=0"
                else -> error(op)
            } },
            identityOf = { null }, uidOfPackage = { null }, mirror = NoSuperuserMirror,
        )
        assertTrue(authority.setAllowed(pkg, false))
        assertTrue(state.grants.isEmpty())
        assertFalse(authority.setAllowed(pkg, true))
    }

    @Test fun staleMirrorWatermarkIsNeverReportedAsApplied() {
        val state = AuthorizationSnapshot(true, emptyMap(), rev = 2)
        val authority = DaemonBootSuperuserAuthority(
            execute = { op, _ -> when (op) {
                "snapshot" -> "wire=${SuperuserWire.encode(state)}"
                "revoke" -> "rev=2"
                "mark-applied" -> "rev=3 pending=1 detail=STALE_MIRROR_REVISION"
                else -> error(op)
            } },
            identityOf = { identity }, uidOfPackage = { uid }, mirror = NoSuperuserMirror,
        )
        assertFalse(authority.setAllowed(pkg, false))
    }

    @Test fun pendingWebReadRetriesTheMirrorAndRejectsAnUnappliedGrant() {
        var synced = false
        var state = AuthorizationSnapshot(true, mapOf(uid to identity), rev = 2,
            applied = listOf(SuperuserApplied("ULTRA_ALLOWLIST", 2, 1, false)))
        val authority = DaemonBootSuperuserAuthority(
            execute = { op, args -> when (op) {
                "snapshot" -> "wire=${SuperuserWire.encode(state)}"
                "mark-applied" -> {
                    val ok = args[2] == "1"
                    state = state.copy(applied = listOf(SuperuserApplied("ULTRA_ALLOWLIST", 2, 2, ok)))
                    "rev=2 pending=${if (ok) 0 else 1}"
                }
                else -> error(op)
            } },
            identityOf = { identity }, uidOfPackage = { uid },
            mirror = object : SuperuserMirror {
                override val backend = "ULTRA_ALLOWLIST"
                override fun apply(snapshot: AuthorizationSnapshot) = MirrorOutcome(synced)
            },
        )
        assertNull(authority.packages())
        synced = true
        assertEquals(setOf(pkg), authority.packages())
        assertFalse(state.pendingApply())
    }

}
