// Fixture: Safe parameterized queries — C#
// Expected: TRUE NEGATIVE (must NOT be flagged)
// Pattern: EF Core LINQ, FromSqlInterpolated, ADO.NET Parameters.AddWithValue

using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;

[ApiController]
[Route("api/[controller]")]
public class SafeUsersController : ControllerBase
{
    private readonly AppDbContext _context;

    // SAFE: EF Core LINQ — fully auto-parameterized
    [HttpGet("search")]
    public IActionResult Search([FromQuery] string query)
    {
        var users = _context.Users
            .Where(u => u.Name.Contains(query))
            .ToList();
        return Ok(users);
    }

    // SAFE: FromSqlInterpolated — auto-parameterizes despite $ syntax
    [HttpGet("{id}")]
    public IActionResult GetUser(int id)
    {
        var users = _context.Users
            .FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {id}")
            .ToList();
        return Ok(users);
    }

    // SAFE: ADO.NET with Parameters.AddWithValue
    [HttpGet("legacy/{id}")]
    public IActionResult GetUserLegacy(string id)
    {
        using var conn = new SqlConnection(_context.Database.GetConnectionString());
        conn.Open();
        using var cmd = new SqlCommand(
            "SELECT * FROM Users WHERE Id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        using var reader = cmd.ExecuteReader();
        // ... read results
        return Ok();
    }

    // SAFE: EF Core ExecuteSqlInterpolated
    [HttpDelete("{name}")]
    public IActionResult DeleteUser(string name)
    {
        _context.Database.ExecuteSqlInterpolated(
            $"DELETE FROM Users WHERE Name = {name}");
        return Ok();
    }
}
