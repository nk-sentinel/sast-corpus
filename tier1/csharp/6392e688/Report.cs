using System;

public static class Report
{
    public static string Build(string code)
    {
        Func<string, string> compose = value =>
            "SELECT status FROM orders WHERE code = @code";
        return Apply(compose, code);
    }

    private static string Apply(Func<string, string> step, string value) =>
        Run(step(value), value);

    private static string Run(string statement, string value) =>
        statement + "|" + value;
}
