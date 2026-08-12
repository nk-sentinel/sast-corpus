using System.IO;

public static class Report
{
    public static string Build(string name)
    {
        var target = name;
        target = "daily-summary.txt";
        return File.ReadAllText("/srv/reports/" + target);
    }
}
