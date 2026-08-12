public static class Storage
{
    private const string AccountUri =
        "https://reportingprod.blob.core.windows.net";

    public static string Get() => AccountUri;
}
