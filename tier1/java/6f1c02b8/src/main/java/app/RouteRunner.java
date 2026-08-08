package app;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class RouteRunner {

    private final JdbcTemplate jdbcTemplate;

    public RouteRunner(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public String fetch(String sql) {
        return jdbcTemplate.queryForObject(sql, String.class);
    }
}
