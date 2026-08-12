using System.IO;

public static class Report
{
    private sealed class Request
    {
        public string Name { get; set; }
    }

    public static string Build(string name)
    {
        var request = new Request();
        request.Name = name;
        return Read(request);
    }

    private static string Read(Request request)
    {
        return File.ReadAllText("/srv/reports/" + request.Name);
    }
}
