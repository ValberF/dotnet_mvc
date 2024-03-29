using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MvcMovie.Data;
using MvcMovie.Data.Security;
using MvcMovie.Data.Security.Interface;
using MvcMovie.Models;

namespace MvcMovie.Controllers;
public class LoginController : Controller
{
   private readonly MvcMovieContext _context;
   private readonly IUtils _utils;

   public LoginController(MvcMovieContext context, IUtils utils)
   {
      _context = context;
      _utils = utils;
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
         user.Password = _utils.HashPassword(user.Password ?? "");
         var userInDb = await _context.User.FirstOrDefaultAsync(u => u.Email == user.Email && u.Password == user.Password);

         if (userInDb != null)
         {
            if (userInDb.Email == "kayquepiton@gmail.com")
            {
               var token = _utils.GenerateJwtToken(userInDb.Email, "admin");
               Response.Cookies.Append("token", token, new CookieOptions
               {
                  HttpOnly = true,
                  Expires = DateTime.Now.AddMinutes(60)
               });
               return RedirectToAction("Index", "Home");
            }
            else
            {
               var token = _utils.GenerateJwtToken(userInDb.Email, "user");
               Response.Cookies.Append("token", token, new CookieOptions
               {
                  HttpOnly = true,
                  Expires = DateTime.Now.AddMinutes(60)
               });
               return RedirectToAction("Index", "Home");
            }

         }
      }
      return Unauthorized();
   }
}
