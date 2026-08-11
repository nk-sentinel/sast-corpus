using System.IO;

namespace App;

public static class Work
{
    private const string Base = "/srv/reports";

    public static object Render(string name)
    {
        var target = Path.GetFullPath(Path.Combine(Base, Path.GetFileName(name)));
        if (!target.StartsWith(Base + Path.DirectorySeparatorChar))
        {
            throw new IOException(name);
        }
        return File.ReadAllText(target);
    }
}
