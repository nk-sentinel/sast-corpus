package app;

import java.io.InputStream;

public class Runner {
    static String handle(String name) throws Exception {
        String line = "tar -cf backup.tar " + name;
        Process process = Runtime.getRuntime().exec(new String[] {"sh", "-c", line});
        InputStream stream = process.getInputStream();
        return new String(stream.readAllBytes());
    }
}
