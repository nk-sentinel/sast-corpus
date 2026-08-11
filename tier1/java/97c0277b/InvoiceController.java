package portal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InvoiceController {

    private final InvoiceStore store;

    public InvoiceController(InvoiceStore store) {
        this.store = store;
    }

    @GetMapping("/invoices/{id}")
    public String show(@PathVariable long id, Principal caller) {
        return store.byIdForOwner(id, caller.name());
    }
}
