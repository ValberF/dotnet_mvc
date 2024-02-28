using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MvcMovie.Data;
using MvcMovie.Models;

namespace MvcMovie.Controllers
{
   public class LoginController : Controller
   {
      private readonly MvcMovieContext _context;
      private readonly IConfiguration _configuration;

      public LoginController(MvcMovieContext context, IConfiguration configuration)
      {
         _context = context;
         _configuration = configuration;
      }

      // GET: Login/Index
      public IActionResult Index()
      {
         return View();
      }

      // POST: Login/Authenticate
      [HttpPost]
      [ValidateAntiForgeryToken]
      public async Task<IActionResult> Login([Bind("Email,Password")] Login user)
      {
         if (ModelState.IsValid)
         {
            user.Password = HashPassword(user.Password ?? "");
            var userInDb = await _context.User.FirstOrDefaultAsync(u => u.Email == user.Email && u.Password == user.Password);

            if (userInDb != null)
            {
               // Se o usuário for autenticado com sucesso, gere um token JWT
               var token = GenerateJwtToken(userInDb.Email, "user");
               HttpContext.Session.SetString("JwtToken", token);
               return Ok(new { token });
            }
         }
         return Unauthorized();
      }

      // Método para gerar um token JWT

    public string GenerateJwtToken(string email, string role)
    {
        var issuer = _configuration["Jwt:Issuer"];
        var audience = _configuration["Jwt:Audience"];
        var key = _configuration["Jwt:Key"];
        //cria uma chave utilizando criptografia simétrica
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
        //cria as credenciais do token
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
         new Claim("userName", email),
         new Claim(ClaimTypes.Role, role)
      };

        var token = new JwtSecurityToken( //cria o token
           issuer: issuer, //emissor do token
           audience: audience, //destinatário do token
           claims: claims, //informações do usuário
           expires: DateTime.Now.AddMinutes(30), //tempo de expiração do token
           signingCredentials: credentials); //credenciais do token


        var tokenHandler = new JwtSecurityTokenHandler(); //cria um manipulador de token

        var stringToken = tokenHandler.WriteToken(token);

        return stringToken;
    }

      public static string HashPassword(string password)
      {
         using (SHA256 sha256Hash = SHA256.Create())
         {
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(password));

            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
               builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
         }
      }
   }
}
