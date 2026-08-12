import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class Report {
    private static final class Request {
        private String name;
        void setName(String value) {
            this.name = Paths.get(value).getFileName().toString();
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
            Path base = Paths.get("/srv/reports").toRealPath();
            Path target = base.resolve(request.getName()).normalize();
            if (!target.startsWith(base)) {
                return "";
            }
            return new String(Files.readAllBytes(target));
        } catch (IOException e) {
            return "";
        }
    }
}
