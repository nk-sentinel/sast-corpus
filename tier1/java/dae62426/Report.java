import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public final class Report {
    public static String build(String name) {
        Map<String, String> params = new HashMap<>();
        params.put("target", name);
        params.put("mode", "summary");
        return run(params.get("target"));
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
