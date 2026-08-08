package app;

import java.util.Base64;

public class Runner {
    static String handle(String blob) throws Exception {
        byte[] raw = Base64.getDecoder().decode(blob);
        return new String(raw).trim();
    }
}
