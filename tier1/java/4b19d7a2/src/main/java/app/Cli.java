package app;

import java.sql.Connection;
import java.sql.DriverManager;

public class Cli {
    public static void main(String[] args) throws Exception {
        Connection connection = DriverManager.getConnection(args[1]);
        OrderRepository repository = new OrderRepository(connection);
        System.out.println(repository.findByReference(args[0]));
    }
}
