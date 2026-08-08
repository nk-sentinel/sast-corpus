using Microsoft.Data.SqlClient;

namespace App;

public static class Store
{
    public static object Lookup(string code)
    {
        var statement = "SELECT status FROM orders WHERE code = @code";
        using var command = new SqlCommand(statement);
        command.Parameters.AddWithValue("@code", code);
        return command.ExecuteScalar();
    }
}
