public static class Report
{
    public static string Build(string code)
    {
        return Run("SELECT status FROM orders WHERE code = @code", code);
    }

    private static string Run(string statement, string value)
    {
        using var link = new Microsoft.Data.SqlClient.SqlConnection("Server=.;Database=app");
        using var command = new Microsoft.Data.SqlClient.SqlCommand(statement, link);
        command.Parameters.AddWithValue("@code", value);
        return command.ExecuteScalar()?.ToString() ?? "";
    }
}
