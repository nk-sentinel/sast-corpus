package app;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Runner {
    private static final Path BASE = Paths.get("/srv/reports").toAbsolutePath().normalize();

    static String handle(String name) throws Exception {
        Path target = BASE.resolve(Paths.get(name).getFileName()).normalize();
        if (!target.startsWith(BASE)) {
            throw new IllegalArgumentException(name);
        }
        return new String(Files.readAllBytes(target));
    }
}
