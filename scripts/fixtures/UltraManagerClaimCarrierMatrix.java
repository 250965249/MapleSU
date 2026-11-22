import dev.maplesu.manager.ultrakernel.*;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Calls current production Kotlin; writes sparse evidence, never a bootable image. */
public final class UltraManagerClaimCarrierMatrix {
    static void check(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
    }
    static byte[] hex(String value) {
        return HexFormat.of().parseHex(value);
    }
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]), out = Path.of(args[1]), elf = Path.of(args[3]);
        int index = Integer.parseInt(args[2]);
        Path source = root.resolve("work/ultra-native-manager-claim-20261113/carrier-prototype/image-" + index);
        byte[] image = Files.readAllBytes(source.resolve("Image")), before = image.clone();
        var symbols = UltraKernelKallsymsTable.Companion.decode(image);
        Path spec;
        try (var paths = Files.list(root.resolve("work/pre-release-audit-20261113/install-matrix-r2/image-" + index))) {
            spec = paths.filter(p -> p.toString().endsWith(".spec")).findFirst().orElseThrow();
        }
        Map<Long,Map<String,String>> caves = new HashMap<>();
        List<String> specLines = Files.readAllLines(spec, StandardCharsets.UTF_8);
        for (String line : specLines) {
            if (!line.startsWith("#cave=")) continue;
            Map<String,String> fields = new HashMap<>();
            fields.put("role", line.substring(6).split(";",2)[0]);
            for (String part : line.substring(1).split(";")) {
                String[] p = part.split("=",2); fields.put(p[0],p[1]);
            }
            caves.put(Long.valueOf(fields.get("writeStart")), fields);
        }
        var occupied = new ArrayList<UltraKernelPlan.PatchRecord>();
        for (String line : specLines) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] p = line.split("\\|");
            long at = Long.parseLong(p[0]);
            var cave = caves.get(at);
            occupied.add(new UltraKernelPlan.PatchRecord(cave == null ? "occupied" : cave.get("role"), at, hex(p[1]), hex(p[2]),
                cave == null ? null : cave.get("cave"),
                cave == null ? null : Long.valueOf(cave.get("base")),
                cave == null ? null : Integer.valueOf(cave.get("offset")),
                cave == null || !cave.containsKey("shiftedFrom") || cave.get("shiftedFrom").equals("-") ? null : Long.valueOf(cave.get("shiftedFrom"))));
        }
        byte[] bootstrap = Files.readAllBytes(Path.of(args[4]));
        byte[] materializer = Files.readAllBytes(Path.of(args[5]));
        boolean connected = args.length > 7 && args[7].equals("connected");
        var plan = UltraKernelManagerClaimCarrier.INSTANCE.plan(image, symbols, occupied,
            Files.readAllBytes(elf), connected ? Arrays.copyOf(bootstrap, bootstrap.length + 56) : bootstrap,
            materializer, new byte[Integer.parseInt(args[6])]);
        var writes = plan.getRecords();
        if (connected) {
            var combined = UltraKernelManagerClaimCarrier.INSTANCE.connect(image, symbols, occupied,
                new UltraKernelManagerClaimPayload(bootstrap, materializer, Files.readAllBytes(elf)));
            writes = combined.stream().filter(r -> r.getRole().startsWith("manager_claim:")).toList();
            var oldFrame = occupied.stream().filter(r -> r.getRole().equals("arm64_notify_die+0x0")).findFirst().orElseThrow();
            var newFrame = combined.stream().filter(r -> r.getRole().equals(oldFrame.getRole())).findFirst().orElseThrow();
            check(Arrays.equals(Arrays.copyOf(oldFrame.getReplacement(),48), Arrays.copyOf(newFrame.getReplacement(),48)), "FRAME_PROLOGUE_CHANGED");
            check(ByteBuffer.wrap(newFrame.getReplacement()).order(ByteOrder.LITTLE_ENDIAN).getInt(48) ==
                UltraKernelA64.INSTANCE.encodeB(newFrame.getOffset()+48, plan.getBootstrapOffset()+bootstrap.length), "FRAME_RELAY_TARGET");
            var code = writes.stream().filter(r -> r.getRole().equals("manager_claim:bootstrap")).findFirst().orElseThrow();
            var key = occupied.stream().filter(r -> r.getRole().equals("panic+0x0")).findFirst().orElseThrow();
            var gate = occupied.stream().filter(r -> r.getRole().equals("die+0x0")).findFirst().orElseThrow();
            Files.write(out.resolve("connected-relay.bin"),Arrays.copyOfRange(code.getReplacement(),bootstrap.length,code.getReplacement().length));
            Files.write(out.resolve("connected-frame.bin"),newFrame.getReplacement());
            Files.write(out.resolve("connected-credential.bin"),key.getReplacement());
            Files.writeString(out.resolve("connected-entries.tsv"),gate.getOffset()+"\t"+key.getOffset()+"\t"+newFrame.getOffset()+"\n");
        }
        check(Arrays.equals(image, before), "SOURCE_MUTATED");
        Files.createDirectories(out);
        var packed = new ByteArrayOutputStream();
        var rows = new StringBuilder();
        for (var record : writes) {
            long at = record.getOffset();
            int end = (int)(at + record.getLength());
            check(symbols.offsetOf("_stext") <= at && end <= symbols.offsetOf("_etext"), "OUTSIDE_TEXT");
            check(!symbols.hasSymbolIn((int)at, end), "SYMBOL_START_WRITE");
            check(Arrays.equals(record.getOriginal(), Arrays.copyOfRange(before,(int)at,end)), "ORIGINAL_MISMATCH");
            for (int pos=(int)at;pos<end;pos+=4) {
                int word=(before[pos]&255)|((before[pos+1]&255)<<8)|((before[pos+2]&255)<<16)|((before[pos+3]&255)<<24);
                check(word==0 || word==0xd503201f,"NON_PADDING_WRITE");
            }
            packed.write(record.getReplacement());
            rows.append(at).append('\t').append(record.getReplacement().length).append('\t').append(record.getRole()).append('\n');
        }
        Files.write(out.resolve("resolver-carrier-patches.bin"),packed.toByteArray());
        Files.writeString(out.resolve("resolver-carrier-writes.tsv"),rows);
        int[] values = {plan.getBootstrapOffset(),plan.getMaterializerOffset(),plan.getAnchorOffset(),
            plan.getBindingOffset(),plan.getDescriptorOffset(),plan.getDescriptorBytes(),
            plan.getChunkTableOffset(),plan.getChunkCount(),plan.getPayloadEntryOffset(),
            plan.getPayloadMemoryBytes(),plan.getQualifiedPaddingBytes(),plan.getRemainingQualifiedBytes()};
        String[] names = {"bootstrapOffset","materializerOffset","anchorOffset","bindingOffset",
            "descriptorOffset","descriptorBytes","chunkTableOffset","chunkCount","entryOffset",
            "memoryBytes","qualifiedPaddingBytes","remainingQualifiedBytes"};
        var metadata=new StringBuilder();
        for(int n=0;n<values.length;n++) metadata.append(names[n]).append('=').append(values[n]).append('\n');
        metadata.append("descriptorCrc=").append(plan.getDescriptorCrc()).append('\n');
        Files.writeString(out.resolve("production-plan.txt"),metadata);
        System.out.println("image-"+index+" chunks="+plan.getChunkCount()+" remaining="+plan.getRemainingQualifiedBytes());
    }
}
