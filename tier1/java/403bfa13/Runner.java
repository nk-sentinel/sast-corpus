package app;

import java.io.InputStream;
import java.util.List;

public class Runner {
    static String handle(String source) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(List.of("git", "clone", source));
        Process process = builder.start();
        InputStream stream = process.getInputStream();
        return new String(stream.readAllBytes());
    }
}
