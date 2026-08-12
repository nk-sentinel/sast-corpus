using System.Collections.Generic;
using System.Diagnostics;

public static class Report
{
    public static string Build(string name)
    {
        var parameters = new Dictionary<string, string>();
        parameters["target"] = name;
        parameters["mode"] = "summary";
        return Run(parameters["target"]);
    }

    private static string Run(string target)
    {
        Process.Start("/bin/sh", "-c \"/usr/bin/report " + target + "\"");
        return target;
    }
}
