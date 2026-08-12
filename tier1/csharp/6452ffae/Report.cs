using System.Collections.Generic;

public static class Report
{
    public static string Build(string code)
    {
        var holder = new List<string>();
        var same = holder;
        holder.Add(code);
        return Run("SELECT status FROM orders WHERE code = '" + same[0] + "'");
    }

    private static string Run(string statement) => statement;
}
