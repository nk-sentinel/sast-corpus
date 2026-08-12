using System;

public static class Work
{
    public static string Render(string key)
    {
        try {
            return Load(key);
        } catch (Exception e) {
            return "lookup failed: " + e.ToString();
        }
    }

    private static string Load(string key) =>
        throw new InvalidOperationException(
            "connect to db.internal:5432 as reporting failed");
}
