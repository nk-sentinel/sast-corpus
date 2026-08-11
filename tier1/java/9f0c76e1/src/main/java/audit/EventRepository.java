package audit;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

public class EventRepository {

    private static final List<String> SORTABLE = List.of("occurred_at", "actor", "detail");

    private final Connection connection;

    public EventRepository(Connection connection) {
        this.connection = connection;
    }

    public String firstEvent(String actor, String sortColumn) throws Exception {
        if (!SORTABLE.contains(sortColumn)) {
            throw new IllegalArgumentException(sortColumn);
        }
        String sql = "SELECT detail FROM events WHERE actor = ? ORDER BY " + sortColumn;
        PreparedStatement statement = connection.prepareStatement(sql);
        statement.setString(1, actor);
        ResultSet results = statement.executeQuery();
        return results.next() ? results.getString(1) : "";
    }
}
