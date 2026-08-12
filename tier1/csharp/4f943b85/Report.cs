public static class Report
{
    public static string Build(string code)
    {
        return Run("SELECT status FROM orders WHERE code = @code", code);
    }

    private static string Run(string statement, string value) =>
        statement + "|" + value;
}
