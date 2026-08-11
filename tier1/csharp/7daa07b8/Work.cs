using System.IO;

namespace App;

public static class Work
{
    private const string Base = "/srv/reports";

    public static object Render(string name)
    {
        return File.ReadAllText(Path.Combine(Base, name));
    }
}
