using System;

namespace App;

public static class Work
{
    public static object Render(string user) =>
        user + ":" + Environment.GetEnvironmentVariable("DB_PASSWORD");
}
