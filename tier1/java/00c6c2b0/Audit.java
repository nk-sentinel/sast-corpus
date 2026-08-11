package app;

import java.util.logging.Logger;

public class Audit {
    private static final Logger LOGGER = Logger.getLogger("audit");

    static void handle(String user) {
        LOGGER.info("sign-in attempt for " + user);
    }
}
