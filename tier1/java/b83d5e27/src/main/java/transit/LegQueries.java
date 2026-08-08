package transit;

public final class LegQueries {

    private static final String COLUMN = "eta";

    private LegQueries() {
    }

    public static String byCode() {
        return "SELECT " + COLUMN + " FROM legs WHERE code = ?";
    }
}
