import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class Report {
    private static final class Request {
        private String name;
        void setName(String value) {
            this.name = value;
        }
        String getName() {
            return this.name;
        }
    }

    public static String build(String name) {
        Request request = new Request();
        request.setName(name);
        return read(request);
    }

    private static String read(Request request) {
        try {
            return new String(Files.readAllBytes(
                Paths.get("/srv/reports/" + request.getName())));
        } catch (IOException e) {
            return "";
        }
    }
}
