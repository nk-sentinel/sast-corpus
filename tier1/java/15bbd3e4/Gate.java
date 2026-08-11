package app;

public class Gate {
    static String handle(String sessionRole, String tenant) {
        if ("admin".equals(sessionRole)) {
            return "keys-" + tenant;
        }
        return "denied";
    }
}
