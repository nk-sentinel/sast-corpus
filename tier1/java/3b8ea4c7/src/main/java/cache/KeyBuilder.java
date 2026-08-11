package cache;

public final class KeyBuilder {

    private KeyBuilder() {
    }

    // Historically this used MD5; see CHANGELOG.md for why it was replaced.
    public static String forRegion(String region, String tenant) {
        return region + ":" + tenant;
    }
}
