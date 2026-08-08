package transit;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LegController {

    private final LegRunner runner;

    public LegController(LegRunner runner) {
        this.runner = runner;
    }

    @GetMapping("/legs/{code}")
    public String show(@PathVariable String code) {
        return runner.fetch(LegQueries.byCode(), code);
    }
}
