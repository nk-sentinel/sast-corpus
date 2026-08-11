package portal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {

    @PreAuthorize("permitAll()")
    @GetMapping("/health")
    public String health() {
        return "ok";
    }

    @PreAuthorize("permitAll()")
    @GetMapping("/version")
    public String version() {
        return "2.1.0";
    }
}
