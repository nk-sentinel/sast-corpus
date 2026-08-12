using System;

public static class Cli
{
    public static void Main(string[] args)
    {
        Console.WriteLine(Report.Build(args.Length > 0 ? args[0] : ""));
    }
}
