using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MvcMovie.Data.Security.Interface;

namespace MvcMovie.Data.Security;

public class Utils : IUtils
{
    private readonly IConfiguration _configuration;

    public Utils(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public string HashPassword(string password)
    {
        using (var sha256 = SHA256.Create())
         {
               var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
               var hash = BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
               return hash;
         }
    }

    public string GenerateJwtToken(string email, string role)
   {
      var issuer = _configuration["Jwt:Issuer"];
      var audience = _configuration["Jwt:Audience"];
      var key = _configuration["Jwt:Key"];
      var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
      var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
      
      var claims = new[]
      {
         new Claim("userName", email),
         new Claim(ClaimTypes.Role, role)
      };

      var token = new JwtSecurityToken( 
         issuer: issuer,
         audience: audience,
         claims: claims,
         expires: DateTime.Now.AddMinutes(30),
         signingCredentials: credentials);
      

      var tokenHandler = new JwtSecurityTokenHandler();

      var stringToken = tokenHandler.WriteToken(token);

      return stringToken;
   }
}
