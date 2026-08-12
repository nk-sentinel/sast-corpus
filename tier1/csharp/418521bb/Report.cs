using System.Collections.Generic;
using System.Diagnostics;

public static class Report
{
    private static readonly Dictionary<string, string> Allowed =
        new Dictionary<string, string> { { "daily", "daily" }, { "weekly", "weekly" } };

    public static string Build(string name)
    {
        if (!Allowed.TryGetValue(name, out var target))
        {
            return "";
        }
        return Run(target);
    }

    private static string Run(string target)
    {
        Process.Start("/usr/bin/report", target);
        return target;
    }
}
