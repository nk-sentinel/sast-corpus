package app;

import java.io.IOException;
import java.io.InputStream;

public class Intake {
    private static final int MAX_BYTES = 1048576;

    static int handle(InputStream stream) throws Exception {
        byte[] payload = stream.readNBytes(MAX_BYTES + 1);
        if (payload.length > MAX_BYTES) {
            throw new IOException("too large");
        }
        return payload.length;
    }
}
