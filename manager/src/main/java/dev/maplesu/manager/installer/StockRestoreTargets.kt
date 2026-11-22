package dev.maplesu.manager.installer

import org.json.JSONObject
import java.security.MessageDigest

/** The caller reads only root-owned native records while holding the device lock. */
internal object StockRestoreTargets {
    data class Selection(val targets: Set<String>, val sourceProofs: Map<String, String> = emptyMap(),
                         val coverage: String = "FULL_NO_CURRENT_INSTALL")

    private val carriers = setOf("boot", "init_boot")
    private val complete = setOf("REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED")

    fun select(snapshot: InstallerSnapshot, targetMode: String, records: List<JSONObject>, currentBootId: String): Selection {
        val full = Selection(snapshot.partitions.keys.filter { it in carriers }.toSet())
        check("boot" in full.targets) { "INSTALLER_STOCK_TARGETS_INVALID" }
        val current = records.filter { matches(it, snapshot, currentBootId) }
        if (current.isEmpty()) return full
        if (current.any { it.optString("targetMode") != targetMode })
            return full.copy(coverage = "FULL_CROSS_MODE_INSTALL")
        if (current.any { record -> record.optString("signingMode").isNotEmpty() && runCatching {
            val rows = record.getJSONObject("snapshot").getJSONObject("partitions")
            val expected = record.getJSONObject("expected")
            val signing = when (record.getString("signingMode")) {
                "CHAINED", "NON_CHAINED" -> setOf("vbmeta")
                "AOSP" -> setOf("vbmeta", "recovery", "vbmeta_system")
                else -> return@runCatching true
            }
            check(signing.all { rows.has(it) && expected.has(it) })
            // expected records the padded final bytes for every tracked partition, including
            // signing outputs that may be byte-identical to PRE. The mode alone is not a write set.
            val changed = expected.keys().asSequence().filter { name ->
                val before = rows.getJSONObject(name).getString("sha256")
                val after = expected.getString(name)
                check(before.matches(Regex("[0-9a-f]{64}")) && after.matches(Regex("[0-9a-f]{64}")))
                before != after
            }.toSet()
            val declared = setOf(record.getString("partition")) + compatibility(record)
            changed.any { it !in declared || it !in carriers }
        }.getOrDefault(true) }) return full.copy(coverage = "FULL_SIGNED_INSTALL")
        if (current.any { !it.has("compatibilityPartitions") || compatibility(it).any { name -> name !in carriers } })
            return full.copy(coverage = "FULL_COMPATIBILITY_UNCLOSED")
        val targets = current.map { record ->
            setOf(record.getString("partition")) + compatibility(record)
        }
        check(targets.distinct().size == 1) { "INSTALLER_STOCK_TARGETS_AMBIGUOUS" }
        val proofs = current.associate { it.getString("taskId") to proof(it) }
        check(proofs.size == current.map { it.getString("taskId") }.distinct().size && current.all {
            proofs[it.getString("taskId")] == proof(it)
        }) { "INSTALLER_STOCK_TARGETS_AMBIGUOUS" }
        return Selection(targets.first(), proofs.toSortedMap(), "CURRENT_NATIVE_INSTALL")
    }

    private fun compatibility(record: JSONObject): Set<String> {
        val rows = record.getJSONArray("compatibilityPartitions")
        return (0 until rows.length()).map { rows.getString(it) }.toSet()
    }

    private fun matches(record: JSONObject, snapshot: InstallerSnapshot, currentBootId: String): Boolean = runCatching {
        check(record.getInt("schema") == 1 && record.getString("kind") == "NATIVE" &&
            record.getString("operation") == "INSTALL" && record.getString("state") in complete &&
            record.optString("error").isEmpty() && record.optString("rebootSourceState") != "RESTORED")
        check(record.getString("taskId").isNotEmpty() && record.getString("bootId").isNotEmpty() &&
            record.getString("partition") in carriers && record.getString("partition") in snapshot.partitions)
        val before = record.getJSONObject("snapshot")
        check(before.getString("firmware") == snapshot.firmware && before.getString("slotSuffix") == snapshot.slotSuffix)
        val rows = before.getJSONObject("partitions")
        val oldNames = rows.keys().asSequence().toSet()
        val signed = record.optString("signingMode").isNotEmpty()
        check(snapshot.partitions.keys.all { it in oldNames } &&
            (oldNames - snapshot.partitions.keys).all { signed && it in setOf("recovery", "vbmeta_system") })
        val expected = record.getJSONObject("expected")
        val tracked = oldNames.filter { it in carriers || it == "vendor_boot" || signed && it in setOf("vbmeta", "recovery", "vbmeta_system") }.toSet()
        check(expected.keys().asSequence().toSet() == tracked)
        snapshot.partitions.forEach { (name, now) ->
            val old = rows.getJSONObject(name)
            val identity = requireNotNull(now.identity)
            check(old.getString("resolvedPath") == now.resolvedPath && old.getLong("size") == now.size &&
                old.getLong("deviceNumber") == identity.deviceNumber)
            if (record.getString("bootId") == currentBootId)
                check(old.getLong("inode") == identity.inode && old.getLong("filesystem") == identity.filesystem)
            val hash = if (name in tracked) expected.getString(name) else old.getString("sha256")
            check(hash.matches(Regex("[0-9a-f]{64}")) && hash == now.sha256)
        }
        if (record.has("compatibilityPartitions")) {
            val items = compatibility(record)
            check(items.all { it in snapshot.partitions && it != record.getString("partition") })
        }
        true
    }.getOrDefault(false)

    private fun proof(record: JSONObject): String {
        val rows = record.getJSONObject("snapshot").getJSONObject("partitions")
        val expected = record.getJSONObject("expected")
        val text = listOf("taskId", "targetMode", "partition", "bootId", "signingMode").joinToString("\n") { record.optString(it) } +
            "\n" + record.getJSONObject("snapshot").getString("firmware") + "\n" +
            record.getJSONObject("snapshot").getString("slotSuffix") + "\n" + compatibility(record).sorted().joinToString(",") +
            "\n" + rows.keys().asSequence().sorted().joinToString("\n") { name ->
                val row = rows.getJSONObject(name)
                name + ":" + listOf("resolvedPath", "size", "sha256", "deviceNumber", "inode", "filesystem")
                    .joinToString(":") { row.get(it).toString() } + ":" + expected.optString(name)
            }
        return MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    fun requireSameTargets(actual: Set<String>, selection: Selection) {
        check(actual.isNotEmpty() && actual == selection.targets) { "INSTALLER_STOCK_TARGETS_INVALID" }
    }

    fun restorationKind(record: JSONObject): ImageRestorationKind {
        val kind = ImageRestorationKind.fromWire(record.optString("restorationKind"))
        val owned = record.optString("originalSource") == "maplesu-owned" || record.has("ownedRemovalProof") ||
            record.optString("stockRestoreCoverage") == "IMAGE_OWNED_RECORD"
        check(!owned || kind == ImageRestorationKind.OWNED_WRITES_REMOVED) { "INSTALLER_RESTORATION_KIND_INVALID" }
        return kind
    }

    /** Source records are re-read by the root adapter; the snapshot is this restore task's PRE. */
    fun saved(record: JSONObject, snapshot: InstallerSnapshot, sourceRecords: List<JSONObject>): Set<String> {
        if (restorationKind(record) == ImageRestorationKind.OWNED_WRITES_REMOVED) {
            val targets = record.getJSONArray("stockRestoreTargets")
            val proof = record.getJSONObject("ownedRemovalProof")
            val originals = record.getJSONObject("originals")
            val carrier = targets.optString(0).takeIf { targets.length() == 1 && it in carriers }
            val row = snapshot.partitions[carrier]
            check(record.optString("operation") == "RESTORE_STOCK" &&
                record.optString("originalSource") == "maplesu-owned" &&
                (record.optString("ownedRemovalSource") in setOf("IMAGE_BOUND_KERNEL_REVERSE", "ARCHIVED_KERNEL_REVERSE",
                    "IMAGE_BOUND_EXACT_INPUT") && carrier == "boot" ||
                    record.optString("ownedRemovalSource") == "IMAGE_BOUND_INIT_BOOT_INPUT" && carrier == "init_boot") &&
                record.optString("stockRestoreCoverage") == "IMAGE_OWNED_RECORD" &&
                record.getJSONObject("stockRestoreSources").length() == 0 &&
                carrier != null && row != null &&
                proof.keys().asSequence().toSet() == setOf(carrier) && proof.getString(carrier) == row.sha256 &&
                originals.keys().asSequence().toSet() == setOf(carrier) &&
                originals.getString(carrier).matches(Regex("[0-9a-f]{64}")) && originals.getString(carrier) != row.sha256) {
                "INSTALLER_STOCK_TARGETS_INVALID"
            }
            return setOf(requireNotNull(carrier))
        }
        val full = snapshot.partitions.keys.filter { it in carriers }.toSet() +
            if (record.optJSONObject("originals")?.has("vendor_boot") == true) setOf("vendor_boot") else emptySet()
        check("boot" in full) { "INSTALLER_STOCK_TARGETS_INVALID" }
        if (!record.has("stockRestoreTargets")) return full
        val array = record.getJSONArray("stockRestoreTargets")
        val targets = (0 until array.length()).map { array.getString(it) }.toSet()
        check(targets.size == array.length()) { "INSTALLER_STOCK_TARGETS_INVALID" }
        val sources = record.getJSONObject("stockRestoreSources")
        val proofs = sources.keys().asSequence().associateWith { sources.getString(it) }
        val selection = if (proofs.isEmpty()) Selection(full) else
            select(snapshot, record.getString("targetMode"), sourceRecords, record.getString("bootId")).also {
                check(it.sourceProofs == proofs && it.coverage == record.getString("stockRestoreCoverage")) {
                    "INSTALLER_STOCK_TARGETS_INVALID"
                }
            }
        requireSameTargets(targets, selection)
        return targets
    }
}
