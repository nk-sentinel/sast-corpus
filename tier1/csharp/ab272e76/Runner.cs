using System.Diagnostics;

namespace App;

public static class Runner
{
    public static void Archive(string name)
    {
        var line = "-c \"tar -cf backup.tar " + name + "\"";
        Process.Start("/bin/sh", line);
    }
}
