package app;

public final class Settings {
    static final String DB_USER = System.getenv("DB_USER");
    static final String DB_PASSWORD = System.getenv("DB_PASSWORD");

    private Settings() {
    }
}
