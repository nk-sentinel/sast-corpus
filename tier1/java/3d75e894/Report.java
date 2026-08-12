import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public final class Report {
    private static final Map<String, String> ALLOWED = new HashMap<>();
    static {
        ALLOWED.put("daily", "daily");
        ALLOWED.put("weekly", "weekly");
    }

    public static String build(String name) {
        String target = ALLOWED.get(name);
        if (target == null) {
            return "";
        }
        return run(target);
    }

    private static String run(String target) {
        try {
            Runtime.getRuntime().exec("/usr/bin/report " + target);
        } catch (IOException e) {
            return "";
        }
        return target;
    }
}
