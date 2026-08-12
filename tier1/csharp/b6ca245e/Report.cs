using System;
using System.Reflection;

public static class Report
{
    public static string Build(string name)
    {
        var type = Type.GetType("System.String");
        var upper = type.GetMethod("ToUpperInvariant", Type.EmptyTypes);
        return (string)upper.Invoke(name, null);
    }
}
