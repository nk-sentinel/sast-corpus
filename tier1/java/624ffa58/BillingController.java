package portal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BillingController {

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/billing/{tenant}/refund")
    public String refund(@PathVariable String tenant) {
        return "refunded-" + tenant;
    }
}
