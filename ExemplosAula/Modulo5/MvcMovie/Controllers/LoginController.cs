using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MvcMovie.Data;
using MvcMovie.Data.Security;
using MvcMovie.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace MvcMovie.Controllers;
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
   // To protect from overposting attacks, enable the specific properties you want to bind to.
   // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
   [HttpPost]
   [ValidateAntiForgeryToken]
   public async Task<IActionResult> Login([Bind("Email,Password")] Login user)
   {
      // Verifica se o modelo é válido
      if (ModelState.IsValid)
      {
         // Criptografa a senha do usuário
         user.Password = Utils.HashPassword(user.Password ?? "");

         // Busca o usuário no banco de dados
         var userInDb = await _context.User.FirstOrDefaultAsync(u => u.Email == user.Email && u.Password == user.Password);

         // Se o usuário existir no banco de dados
         if (userInDb != null)
         {
               // Cria as reivindicações para o token
               var claims = new[]
               {
                  new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                  new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
               };

               // Cria a chave de segurança
               var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
               var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

               // Cria o token
               var token = new JwtSecurityToken(
                  issuer: _configuration["Jwt:Issuer"],
                  audience: _configuration["Jwt:Issuer"],
                  claims: claims,
                  expires: DateTime.Now.AddMinutes(30),
                  signingCredentials: creds
               );

               // Retorna o token
               return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
         }

         // Se o usuário não existir no banco de dados, retorna Unauthorized
         return Unauthorized();
      }

      // Se o modelo não for válido, retorna a visualização de login
      return View(user);
   }

}
