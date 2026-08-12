using Newtonsoft.Json;

public static class Parser
{
    public static object Load(string body) =>
        JsonConvert.DeserializeObject(body);
}
