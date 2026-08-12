import java.io.IOException;

public final class Handler {
    private static boolean permitted(String name) {
        return name.matches("^[a-z-]{1,20}$");
    }

    public static String handle(String name) {
        if (!permitted(name)) {
            return "";
        }
        try {
            Runtime.getRuntime().exec(new String[] {"/usr/bin/report", name});
        } catch (IOException e) {
            return "";
        }
        return name;
    }
}
