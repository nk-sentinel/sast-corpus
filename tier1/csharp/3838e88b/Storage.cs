public static class Storage
{
    private const string ConnectionString =
        "DefaultEndpointsProtocol=https;AccountName=reportingprod;"
        + "AccountKey=kR8vN2mQ7xJ4pL9wT6yB3nH5sD1fG0aZcX8eU2iOnQ7kV3mB9wT4yD6nH2sG8fA1zZcXe5iOnQ==;"
        + "EndpointSuffix=core.windows.net";

    public static string Get() => ConnectionString;
}
