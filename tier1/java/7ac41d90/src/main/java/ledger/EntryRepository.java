package ledger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class EntryRepository {

    private final Connection connection;

    public EntryRepository(Connection connection) {
        this.connection = connection;
    }

    public String balanceFor(String account) throws Exception {
        String sql = "SELECT balance FROM entries WHERE account = '" + account + "'";
        PreparedStatement statement = connection.prepareStatement(sql);
        ResultSet results = statement.executeQuery();
        return results.next() ? results.getString(1) : "";
    }
}
