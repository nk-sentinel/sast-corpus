package app;

import java.io.InputStream;
import java.util.List;

public class Runner {
    static String handle(String name) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(List.of("tar", "-cf", "backup.tar", name));
        Process process = builder.start();
        InputStream stream = process.getInputStream();
        return new String(stream.readAllBytes());
    }
}
