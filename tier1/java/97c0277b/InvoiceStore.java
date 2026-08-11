package portal;

public class InvoiceStore {

    public String byId(long id) {
        return "invoice-" + id;
    }

    public String byIdForOwner(long id, String owner) {
        return "invoice-" + id + "-" + owner;
    }
}
