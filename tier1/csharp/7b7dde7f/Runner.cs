using System.Diagnostics;

namespace App;

public static class Runner
{
    public static void Archive(string name)
    {
        var info = new ProcessStartInfo("tar");
        info.ArgumentList.Add("-cf");
        info.ArgumentList.Add("backup.tar");
        info.ArgumentList.Add(name);
        Process.Start(info);
    }
}
