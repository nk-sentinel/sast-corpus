public static class Work
{
    public static string Render(string user)
    {
        var flat = user.Replace("\n", "").Replace("\r", "");
        return "level=info action=login user=" + flat;
    }
}
