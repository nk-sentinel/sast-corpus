using Microsoft.AspNetCore.Mvc;

namespace App;

[ApiController]
[Route("show")]
public class ReportController : ControllerBase
{
    [HttpGet]
    public void Show([FromQuery] string name) => Runner.Archive(name);
}
