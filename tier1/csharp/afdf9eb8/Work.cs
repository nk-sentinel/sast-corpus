using System.Security.Cryptography;
using System.Text;

namespace App;

public static class Work
{
    public static object Render(string value)
    {
        using var algorithm = MD5.Create();
        return algorithm.ComputeHash(Encoding.UTF8.GetBytes(value));
    }
}
