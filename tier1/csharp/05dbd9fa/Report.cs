using System.IO;

public static class Report
{
    private const string Base = "/srv/reports";

    private sealed class Request
    {
        public string Name { get; set; }
    }

    public static string Build(string name)
    {
        var request = new Request();
        request.Name = Path.GetFileName(name);
        return Read(request);
    }

    private static string Read(Request request)
    {
        var target = Path.GetFullPath(Path.Combine(Base, request.Name));
        if (!target.StartsWith(Base + Path.DirectorySeparatorChar))
        {
            return "";
        }
        return File.ReadAllText(target);
    }
}
