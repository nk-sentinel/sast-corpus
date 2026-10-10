using Microsoft.AspNetCore.Mvc;

namespace App;

[ApiController]
[Route("show")]
public class ReportController : ControllerBase
{
    [HttpGet]
    public object Show([FromQuery] string code) => Store.Lookup(code);
}
