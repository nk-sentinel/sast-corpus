namespace App;

public class Controller
{
    public object Show(string code) => Store.Lookup(code);
}
