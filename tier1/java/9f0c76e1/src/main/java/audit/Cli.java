package audit;

import java.sql.Connection;
import java.sql.DriverManager;

public class Cli {
    public static void main(String[] args) throws Exception {
        Connection connection = DriverManager.getConnection(args[2]);
        System.out.println(new EventRepository(connection).firstEvent(args[0], args[1]));
    }
}
