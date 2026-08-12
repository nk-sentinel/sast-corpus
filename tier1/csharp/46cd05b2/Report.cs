using System.IO;

public static class Report
{
    public static string Build(string name)
    {
        var target = name;
        return File.ReadAllText("/srv/reports/" + target);
    }
}
