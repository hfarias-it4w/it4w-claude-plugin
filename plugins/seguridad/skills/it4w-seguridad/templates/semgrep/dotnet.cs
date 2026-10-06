using System;
public class A : ControllerBase
{
    // ruleid: escritura-sin-authorize
    [HttpPost]
    public IActionResult Malo1() { return Ok(); }

    // ruleid: escritura-sin-authorize
    [HttpPost("ruta")]
    public async Task<IActionResult> Malo2() { return Ok(); }

    // ruleid: escritura-sin-authorize
    [HttpDelete("{id}")]
    public IActionResult Malo3(int id) { return Ok(); }

    // ruleid: escritura-sin-authorize
    [HttpPatch("{id}")]
    [ProducesResponseType(200)]
    public IActionResult Malo4(int id) { return Ok(); }

    // ruleid: escritura-sin-authorize
    [HttpPost("publica")]
    [AllowAnonymous]
    public IActionResult MaloAnonimo() { return Ok(); }

    // ok: escritura-sin-authorize
    [Authorize]
    [HttpPost]
    public IActionResult Bueno1() { return Ok(); }

    // ok: escritura-sin-authorize
    [Authorize(Roles = "x")]
    [HttpPut("{id}")]
    public IActionResult Bueno2(int id) { return Ok(); }

    // ok: escritura-sin-authorize
    [HttpPost("a")]
    [Authorize(Policy = "p")]
    public IActionResult Bueno3() { return Ok(); }

    // ok: escritura-sin-authorize
    [HttpPost("b")]
    [ProducesResponseType(200)]
    [Authorize]
    public async Task<ActionResult<int>> Bueno4() { return Ok(1); }

    // ok: escritura-sin-authorize
    [HttpGet]
    public IActionResult Lectura() { return Ok(); }
}

[Authorize]
public class B : ControllerBase
{
    // ok: escritura-sin-authorize
    [HttpPost]
    public IActionResult BuenoClaseSinParentesis() { return Ok(); }
}

[ApiController]
[Authorize(Policy = "p")]
public class C : ControllerBase
{
    // ok: escritura-sin-authorize
    [HttpPost("x")]
    public IActionResult BuenoClaseConPolicy() { return Ok(); }
}
