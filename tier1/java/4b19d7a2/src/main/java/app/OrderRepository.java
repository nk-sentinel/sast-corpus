package app;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class OrderRepository {
    private final Connection connection;

    public OrderRepository(Connection connection) {
        this.connection = connection;
    }

    public String findByReference(String reference) throws Exception {
        StringBuilder builder = new StringBuilder("SELECT status FROM orders WHERE reference = '");
        builder.append(reference);
        builder.append("'");
        Statement statement = connection.createStatement();
        ResultSet results = statement.executeQuery(builder.toString());
        return results.next() ? results.getString(1) : "";
    }
}
