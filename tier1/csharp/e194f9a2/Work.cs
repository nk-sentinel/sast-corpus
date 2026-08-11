using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace App;

public static class Work
{
    public static object Render(string blob)
    {
        var raw = Convert.FromBase64String(blob);
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(new MemoryStream(raw));
    }
}
