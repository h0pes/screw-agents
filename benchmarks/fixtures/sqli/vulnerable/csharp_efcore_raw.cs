// Fixture: cs-ef-raw-concat + cs-sqlcmd-interp — EF Core and ADO.NET injection
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-89
// Pattern: ExecuteSqlRaw with concatenation, SqlCommand with interpolation

using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly AppDbContext _context;

    // VULNERABLE: ExecuteSqlRaw with String.Format
    [HttpDelete("{name}")]
    public IActionResult DeleteUser(string name)
    {
        _context.Database.ExecuteSqlRaw(
            string.Format("DELETE FROM Users WHERE Name = '{0}'", name));
        return Ok();
    }

    // VULNERABLE: FromSqlRaw with string concatenation
    [HttpGet("search")]
    public IActionResult Search([FromQuery] string query)
    {
        var users = _context.Users
            .FromSqlRaw("SELECT * FROM Users WHERE Name LIKE '%" + query + "%'")
            .ToList();
        return Ok(users);
    }

    // VULNERABLE: SqlCommand with string interpolation
    [HttpGet("{id}")]
    public IActionResult GetUser(string id)
    {
        using var conn = new SqlConnection(_context.Database.GetConnectionString());
        conn.Open();
        using var cmd = new SqlCommand(
            $"SELECT * FROM Users WHERE Id = {id}", conn);
        using var reader = cmd.ExecuteReader();
        // ... read results
        return Ok();
    }
}
