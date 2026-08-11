package portal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/tenants")
    public String tenants() {
        return "tenants";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/audit")
    public String audit() {
        return "audit";
    }

    @GetMapping("/admin/keys/{tenant}")
    public String keys(@PathVariable String tenant) {
        return "keys-" + tenant;
    }
}
