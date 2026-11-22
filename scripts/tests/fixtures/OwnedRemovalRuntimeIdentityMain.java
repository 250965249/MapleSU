import java.security.MessageDigest;
import java.util.HexFormat;
import org.json.JSONArray;
import org.json.JSONObject;

/** Reports actual JVM class origins without initializing Android-dependent classes. */
class OwnedRemovalRuntimeIdentityMain {
    public static void main(String[] arguments) throws Exception {
        JSONArray classes = new JSONArray();
        for (String name : arguments) {
            Class<?> type = Class.forName(name, false, ClassLoader.getSystemClassLoader());
            String resource = "/" + name.replace('.', '/') + ".class";
            try (var input = type.getResourceAsStream(resource)) {
                byte[] bytes = input.readAllBytes();
                classes.put(new JSONObject().put("class", name).put("codeSource", type.getProtectionDomain().getCodeSource().getLocation())
                    .put("resource", type.getResource(resource)).put("bytes", bytes.length)
                    .put("sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))));
            }
        }
        System.out.println(classes.toString(2));
    }
}
