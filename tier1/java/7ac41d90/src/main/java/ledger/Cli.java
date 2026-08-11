package ledger;

import java.sql.Connection;
import java.sql.DriverManager;

public class Cli {
    public static void main(String[] args) throws Exception {
        Connection connection = DriverManager.getConnection(args[1]);
        System.out.println(new EntryRepository(connection).balanceFor(args[0]));
    }
}
