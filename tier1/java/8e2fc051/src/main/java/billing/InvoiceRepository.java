package billing;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class InvoiceRepository {
    private static final String COLUMNS = "status, issued_on";

    private final Connection connection;

    public InvoiceRepository(Connection connection) {
        this.connection = connection;
    }

    public String findByReference(String reference) throws Exception {
        StringBuilder builder = new StringBuilder("SELECT ");
        builder.append(COLUMNS);
        builder.append(" FROM invoices WHERE reference = ?");
        PreparedStatement statement = connection.prepareStatement(builder.toString());
        statement.setString(1, reference);
        ResultSet results = statement.executeQuery();
        return results.next() ? results.getString(1) : "";
    }
}
