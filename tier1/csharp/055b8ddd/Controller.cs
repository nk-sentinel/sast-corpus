namespace App;

public class Controller
{
    public object Show(string value) => Work.Render(value);
}
