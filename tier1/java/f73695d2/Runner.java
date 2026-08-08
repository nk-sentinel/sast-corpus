package app;

import java.nio.file.Files;
import java.nio.file.Path;

public class Runner {
    private static final String BASE = "/srv/reports";

    static String handle(String name) throws Exception {
        Path target = Path.of(BASE, name);
        return new String(Files.readAllBytes(target));
    }
}
