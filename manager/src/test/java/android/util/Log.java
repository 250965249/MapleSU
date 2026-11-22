package android.util;

/** Host fixture for the SDK client's missing-native-library diagnostic. */
public final class Log {
    private Log() {}
    public static boolean isLoggable(String tag, int priority) { return false; }
    public static int w(String tag, String message, Throwable error) { return 0; }
}
