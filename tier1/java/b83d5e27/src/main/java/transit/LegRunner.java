package transit;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class LegRunner {

    private final JdbcTemplate jdbcTemplate;

    public LegRunner(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public String fetch(String sql, String code) {
        return jdbcTemplate.queryForObject(sql, String.class, code);
    }
}
