package audit;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class EventRepository {

    private final Connection connection;

    public EventRepository(Connection connection) {
        this.connection = connection;
    }

    public String firstEvent(String actor, String sortColumn) throws Exception {
        String sql = "SELECT detail FROM events WHERE actor = ? ORDER BY " + sortColumn;
        PreparedStatement statement = connection.prepareStatement(sql);
        statement.setString(1, actor);
        ResultSet results = statement.executeQuery();
        return results.next() ? results.getString(1) : "";
    }
}
