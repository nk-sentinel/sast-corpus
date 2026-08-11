package portal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {

    @GetMapping("/internal/tenants/{tenant}/secrets")
    public String secrets(@PathVariable String tenant) {
        return "secrets-" + tenant;
    }

    @PreAuthorize("permitAll()")
    @GetMapping("/health")
    public String health() {
        return "ok";
    }
}
