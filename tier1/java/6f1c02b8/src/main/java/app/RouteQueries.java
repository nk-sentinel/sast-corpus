package app;

public final class RouteQueries {

    private RouteQueries() {
    }

    public static String forCode(String code) {
        return "SELECT eta FROM routes WHERE code = '" + code + "'";
    }
}
