package app;

import java.util.Map;

public final class Session {
    private static final Map<String, String> ROLES = Map.of("s-1", "admin");

    private Session() {
    }

    static String roleOf(String sessionId) {
        return ROLES.getOrDefault(sessionId, "guest");
    }
}
