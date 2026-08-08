package app;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

public class Runner {
    static String handle(String blob) throws Exception {
        byte[] raw = Base64.getDecoder().decode(blob);
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(raw));
        return String.valueOf(stream.readObject());
    }
}
