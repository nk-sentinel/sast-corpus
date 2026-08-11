namespace App;

public static class Work
{
    private const string DbPassword = "Pr0d-Repor7ing-2024!";

    public static object Render(string user) => user + ":" + DbPassword;
}
