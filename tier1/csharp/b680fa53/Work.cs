using System.Text.Json;

namespace App;

public sealed record Settings(string Name);

public static class Work
{
    public static object Render(string blob)
    {
        return JsonSerializer.Deserialize<Settings>(blob) ?? new Settings(string.Empty);
    }
}
