package app;

import java.io.InputStream;

public class Intake {
    static int handle(InputStream stream) throws Exception {
        byte[] payload = stream.readAllBytes();
        return payload.length;
    }
}
