package app;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class ShipmentService {

    private final JdbcTemplate jdbcTemplate;

    public ShipmentService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public String carrierFor(String code) {
        String sql = "SELECT carrier FROM shipments WHERE code = '" + code + "'";
        return jdbcTemplate.queryForObject(sql, String.class);
    }
}
