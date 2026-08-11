using System.IO;
using System.Xml;

namespace App;

public static class Work
{
    public static object Render(string document)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        settings.XmlResolver = null;
        using var reader = XmlReader.Create(new StringReader(document), settings);
        while (reader.Read()) { }
        return true;
    }
}
