package app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RouteController {

    private final RouteRunner runner;

    public RouteController(RouteRunner runner) {
        this.runner = runner;
    }

    @GetMapping("/routes/{code}")
    public String show(@PathVariable String code) {
        return runner.fetch(RouteQueries.forCode(code));
    }
}
