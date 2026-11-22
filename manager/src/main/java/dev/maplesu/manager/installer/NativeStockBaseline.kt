package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPermissions
import dev.maplesu.manager.workmode.control.ShaCheck
import dev.maplesu.manager.workmode.service.RootModeSwitchEnvironmentLifecycle
import dev.maplesu.manager.workmode.storage.MoveSet
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.BaselineResult
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.FileBaselineStore
import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.UUID

/** Root-service adapter for reusing original images independently of the active SDK/session. */
internal object NativeStockBaseline {
    private val control = File(MoveSet.CONTROL_ROOT)
    private val mirrors = File(RootModeSwitchEnvironmentLifecycle.RECOVERY_ROOT, "originals")

    fun originals(snapshot: InstallerSnapshot, output: File,
                  assets: dev.maplesu.manager.ultrakernel.UltraKernelAssetSource? = null,
                  receipts: File? = null, retainedOriginals: List<File> = emptyList()): Map<String, File>? {
        return originals(snapshot, output, control, mirrors, RamdiskBaselineCleanliness(), assets,
            receipts, retainedOriginals)
    }

    /**
     * The caller supplies originals from a verified baseline or the exact stock_image.sha1 KSU
     * backup association. A marker-free live ramdisk alone does not satisfy that contract.
     * Returns the canonical directory; failures leave the approved direct-install path available.
     */
    fun publish(snapshot: InstallerSnapshot, originals: Map<String, File>): String? =
        publish(snapshot, originals, control, mirrors, RamdiskBaselineCleanliness())

    internal fun originalsForRestore(snapshot: InstallerSnapshot, output: File, targets: Set<String>,
        controlRoot: File = control, mirrorRoot: File = mirrors,
        cleanliness: BaselineCleanlinessPort = RamdiskBaselineCleanliness(),
        assets: dev.maplesu.manager.ultrakernel.UltraKernelAssetSource? = null,
        receipts: File? = null, retainedOriginals: List<File> = emptyList()): Map<String, File>? =
        originals(snapshot, output, controlRoot, mirrorRoot, cleanliness, assets, receipts, retainedOriginals,
            restoreTargets = targets)

    internal fun originals(
        snapshot: InstallerSnapshot,
        output: File,
        controlRoot: File,
        mirrorRoot: File,
        cleanliness: BaselineCleanlinessPort,
        assets: dev.maplesu.manager.ultrakernel.UltraKernelAssetSource? = null,
        receipts: File? = null,
        retainedOriginals: List<File> = emptyList(),
        restoreTargets: Set<String>? = null,
    ): Map<String, File>? = runCatching {
        val names = restoreTargets ?: required(snapshot).toSet()
        check(names.isNotEmpty() && names.all { it in setOf("boot", "init_boot") && it in snapshot.partitions })
        val candidates = listOf(File(controlRoot, "boot/baseline"), mirrorRoot)
            .flatMap { it.listFiles()?.filter(File::isDirectory).orEmpty() }
            .map { directory ->
                val json = AtomicControlFile.readUtf8(File(directory, "manifest.json")).orEmpty()
                val created = ControlJsonCodec.decodeOrNull(json, BaselineManifest.serializer())?.createdAt ?: Long.MIN_VALUE
                created to directory
            }
            .sortedByDescending { it.first }
            .asSequence()
            .map { it.second }
            .mapNotNull { directory -> verified(snapshot, directory, cleanliness, names)?.let { it to directory } }
        val (manifest, directory) = candidates.firstOrNull() ?: return null
        if (restoreTargets == null) {
            if (!mirror(directory, File(mirrorRoot, manifest.id))) return null
            val canonical = File(controlRoot, "boot/baseline/${manifest.id}")
            if (!canonical.exists()) {
                privateDirectory(controlRoot)
                if (!mirror(directory, canonical)) return null
            }
        }
        privateDirectory(output)
        val images = names.associateWith { name ->
            val part = manifest.partitions.first { it.name == name }
            File(output, "$name.img").also { target ->
                check(BaselineAtomicFiles.copyVerified(File(directory, "$name.img"), target, part.sha256))
                check(target.length() == part.size)
            }
        }
        // Historical ramdisk-only captures could contain an already patched Ultra kernel.
        // Replace only the transaction copy. The immutable baseline and PRE stay untouched.
        if (assets != null) images["boot"]?.let { boot ->
            val proof = File(output, "kernel-original-proof")
            try {
                val recovery = dev.maplesu.manager.ultrakernel.UltraKernelOriginalRecovery(assets)
                val recovered = if (receipts != null) recovery.recover(boot, receipts, retainedOriginals, proof)
                    else recovery.recoverPinned(boot, proof)
                recovered?.let {
                    check(it.image.length() == boot.length())
                    check(BaselineAtomicFiles.copyVerified(it.image, boot, Hashes.sha256(it.image)))
                }
            } finally { proof.deleteRecursively() }
        }
        images
    }.getOrNull()

    internal fun publish(
        snapshot: InstallerSnapshot,
        originals: Map<String, File>,
        controlRoot: File,
        mirrorRoot: File,
        cleanliness: BaselineCleanlinessPort,
    ): String? = runCatching {
        val names = required(snapshot)
        check(originals.keys.containsAll(names))
        val parts = names.associateWith { name ->
            val image = originals.getValue(name)
            check(image.isFile && !Files.isSymbolicLink(image.toPath()))
            check(image.length() == snapshot.partitions.getValue(name).size)
            BaselinePartitionFacts(name, image.length(), Hashes.sha256(image))
        }
        val facts = BaselineDeviceSnapshot(
            snapshot.slotSuffix, snapshot.firmware, snapshot.kernelRelease, snapshot.selinux, parts,
            snapshot.partitions["vbmeta"]?.let { BaselineVbmetaFacts(true, it.sha256) },
        )
        // Runtime descriptions may change while the same slot's original bytes remain valid.
        // Reuse the original manifest instead of republishing it under a new firmware-derived id.
        val existing = listOf(File(controlRoot, "boot/baseline"), mirrorRoot)
            .flatMap { it.listFiles()?.filter(File::isDirectory).orEmpty() }
            .firstOrNull { directory ->
                verified(snapshot, directory, cleanliness)?.let { manifest ->
                    names.all { name -> manifest.partitions.first { it.name == name }.sha256 == parts.getValue(name).sha256 }
                } == true
            }
        if (existing != null) {
            val canonical = File(controlRoot, "boot/baseline/${existing.name}")
            if (!mirror(existing, File(mirrorRoot, existing.name))) return null
            if (!canonical.exists() && !mirror(existing, canonical)) return null
            if (verified(snapshot, canonical, cleanliness) == null) return null
            return canonical.absolutePath
        }
        val id = BaselineIdentity.fromSnapshot(facts)
        val directory = File(controlRoot, "boot/baseline/$id")
        if (directory.exists()) return null
        privateDirectory(controlRoot)
        val staging = File(controlRoot, "tmp/native-originals-${UUID.randomUUID()}")
        privateDirectory(staging)
        try {
            names.forEach { name ->
                check(BaselineAtomicFiles.copyVerified(originals.getValue(name), File(staging, "$name.img"), parts.getValue(name).sha256))
            }
            val source = object : BaselinePartitionSourcePort {
                override fun snapshot() = facts
                override fun readPartition(name: String, destination: File): BaselinePartitionRead =
                    error("import-only source")
            }
            val store = FileBaselineStore(
                root = controlRoot,
                deviceFacts = { DeviceBootFacts(snapshot.slotSuffix, snapshot.firmware, snapshot.kernelRelease) },
                materializer = InstallerBaselineMaterializer(source, cleanliness,
                    BaselinePatchEvidencePort { BaselinePatchEvidence(true, false, null, "original:image-only") }),
            )
            val imported = BaselineCaptureService(store, source).import(id, staging, BaselineSources.OEM_PACKAGE)
            if (imported !is BaselineResult.Ok || verified(snapshot, directory, cleanliness) == null) return null
            if (mirror(directory, File(mirrorRoot, id))) directory.absolutePath else null
        } finally {
            staging.deleteRecursively()
        }
    }.getOrNull()

    private fun required(snapshot: InstallerSnapshot): List<String> {
        check("boot" in snapshot.partitions)
        return listOf("boot", "init_boot").filter { it in snapshot.partitions }
    }

    private fun verified(
        snapshot: InstallerSnapshot,
        directory: File,
        cleanliness: BaselineCleanlinessPort,
        restoreTargets: Set<String>? = null,
    ): BaselineManifest? = runCatching {
        var parent: File? = directory.absoluteFile
        while (parent != null) {
            check(!Files.isSymbolicLink(parent.toPath()))
            parent = parent.parentFile
        }
        check(directory.isDirectory && !Files.isSymbolicLink(directory.toPath()))
        val file = File(directory, "manifest.json")
        check(!Files.isSymbolicLink(file.toPath()) && AtomicControlFile.verifySha(file) == ShaCheck.OK)
        val manifest = ControlJsonCodec.decodeOrNull(file.readText(), BaselineManifest.serializer()) ?: return null
        check(BaselineIdentity.isValidId(manifest.id) && manifest.id == directory.name)
        check(manifest.schema == BaselineManifest.SCHEMA && manifest.immutable && manifest.clean && manifest.patchMarkers.allAbsent)
        check(manifest.provenance in BaselineSources.ALL && manifest.slot == snapshot.slotSuffix)
        check(manifest.partitions.map { it.name }.distinct().size == manifest.partitions.size)
        val images = (restoreTargets ?: required(snapshot).toSet()).associateWith { name ->
            val part = manifest.partitions.firstOrNull { it.name == name } ?: return null
            check(part.avbTailPreserved && part.size == snapshot.partitions.getValue(name).size)
            File(directory, "$name.img").also { image ->
                check(image.isFile && !Files.isSymbolicLink(image.toPath()) && image.length() == part.size)
                check(Hashes.sha256(image).equals(part.sha256, true))
            }
        }
        val report = cleanliness.verify(images, images.mapValues { it.value.length() },
            BaselinePatchEvidence(true, false, null, "original:image-only"))
        check(report.clean && report.patchMarkers.allAbsent && images.keys.all { report.avbTailPreserved[it] == true })
        manifest
    }.getOrNull()

    private fun privateDirectory(directory: File) {
        var parent: File? = directory.absoluteFile
        while (parent != null) {
            check(!Files.isSymbolicLink(parent.toPath()))
            parent = parent.parentFile
        }
        ControlPermissions.ensureDir(directory)
        ControlPermissions.setPermissions(directory, 0x1c0)
        ControlPermissions.requirePrivateDir(directory)
    }

    /** Copy once. Existing permanent originals are compared and never replaced or cleaned. */
    private fun mirror(source: File, destination: File): Boolean = runCatching {
        if (source.canonicalFile == destination.canonicalFile) return true
        privateDirectory(destination.parentFile!!)
        destination.parentFile!!.parentFile?.takeIf { it.name == "maplesu-recovery" }?.let(::privateDirectory)
        if (destination.exists() || Files.isSymbolicLink(destination.toPath())) return sameTree(source, destination)
        val temporary = File(destination.parentFile, ".${destination.name}.${UUID.randomUUID()}.tmp")
        try {
            Files.walk(source.toPath()).use { paths ->
                paths.forEach { path ->
                    check(!Files.isSymbolicLink(path))
                    val target = temporary.toPath().resolve(source.toPath().relativize(path))
                    Files.copy(path, target, StandardCopyOption.COPY_ATTRIBUTES)
                    if (Files.isRegularFile(target)) FileChannel.open(target, StandardOpenOption.WRITE).use { it.force(true) }
                }
            }
            check(sameTree(source, temporary))
            AtomicControlFile.syncDirectory(temporary)
            Files.move(temporary.toPath(), destination.toPath())
            AtomicControlFile.syncDirectory(destination.parentFile!!)
            true
        } finally {
            temporary.deleteRecursively()
        }
    }.getOrDefault(false)

    private fun sameTree(first: File, second: File): Boolean {
        if (!second.isDirectory || Files.isSymbolicLink(second.toPath())) return false
        fun entries(root: File) = Files.walk(root.toPath()).use { paths ->
            paths.iterator().asSequence().map { root.toPath().relativize(it).toString() }.toList().sorted()
        }
        if (entries(first) != entries(second)) return false
        return entries(first).all { relative ->
            val a = File(first, relative)
            val b = File(second, relative)
            !Files.isSymbolicLink(a.toPath()) && !Files.isSymbolicLink(b.toPath()) &&
                a.isDirectory == b.isDirectory && (a.isDirectory || a.length() == b.length() && Hashes.sha256(a) == Hashes.sha256(b))
        }
    }
}
