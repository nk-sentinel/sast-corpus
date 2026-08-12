using System;
using System.Reflection;

public static class Report
{
    public static string Build(string name)
    {
        var type = Type.GetType("System.Diagnostics.Process, System");
        var start = type.GetMethod("Start", new[] { typeof(string), typeof(string) });
        start.Invoke(null, new object[] { "/bin/sh", "-c \"/usr/bin/report " + name + "\"" });
        return name;
    }
}
