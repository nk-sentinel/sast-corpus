package app;

public class Gate {
    static String handle(String headerRole, String tenant) {
        if ("admin".equals(headerRole)) {
            return "keys-" + tenant;
        }
        return "denied";
    }
}
