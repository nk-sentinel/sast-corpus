import java.util.ArrayList;
import java.util.List;

public final class Report {
    public static String build(String code) {
        List<String> holder = new ArrayList<>();
        List<String> same = holder;
        holder.add(code);
        return run("SELECT status FROM orders WHERE code = '"
                   + same.get(0) + "'");
    }

    private static String run(String statement) {
        return statement;
    }
}
