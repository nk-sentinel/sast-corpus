package depot;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class ParcelService {

    private static final String TABLE = "parcels";

    private final JdbcTemplate jdbcTemplate;

    public ParcelService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public String carrierFor(String code) {
        String sql = "SELECT carrier FROM " + TABLE + " WHERE code = ?";
        return jdbcTemplate.queryForObject(sql, String.class, code);
    }
}
