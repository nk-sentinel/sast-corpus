package billing;

import java.sql.Connection;
import java.sql.DriverManager;

public class Entry {
    public static void main(String[] args) throws Exception {
        Connection connection = DriverManager.getConnection(args[1]);
        InvoiceRepository repository = new InvoiceRepository(connection);
        System.out.println(repository.findByReference(args[0]));
    }
}
