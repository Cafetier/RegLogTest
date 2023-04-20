using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RegLogTest.Data;
using RegLogTest.Models;
using System.IdentityModel.Tokens.Jwt;
using RegLogTest.Services;

namespace RegLogTest.Controllers
{
    [Authorize]
    public class UserController : Controller
    {
        private readonly UserDBContext _context;
        private readonly ITokenService _tokenService;
        private readonly IConfiguration _config;

        public UserController(UserDBContext context, 
            ITokenService tokenService,
            IConfiguration config)
        {
            _context = context;
            _tokenService = tokenService;
            _config = config;
        }

        // GET: User
        public async Task<IActionResult> Index() =>
            View(await _context.Users.ToListAsync());

        // GET: User/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null || _context.Users == null)
                return NotFound();

            var user = await _context.Users
                .FirstOrDefaultAsync(m => m.UserID == id);
            if (user == null) return NotFound();

            return View(user);
        }

        // GET: User/Create
        [AllowAnonymous]
        public IActionResult Create() => View();

        // POST: User/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Create([Bind("UserID,Username,Password")] User user)
        {
            if (!ModelState.IsValid)
                return View(user);
            // hashpassword using bcrypt
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(user.Password);
            user.Password = passwordHash;

            // add to db
            _context.Add(user);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Connect));
        }

        // GET: User/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null || _context.Users == null)
                return NotFound();

            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();
            return View(user);
        }

        // POST: User/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("UserID,Username,Password")] User user)
        {
            if (id != user.UserID) return NotFound();

            if (!ModelState.IsValid) return View(user);
            try
            {
                // hashpassword using bcrypt
                string passwordHash = BCrypt.Net.BCrypt.HashPassword(user.Password);
                user.Password = passwordHash;

                // update user
                _context.Update(user);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserExists(user.UserID))
                    return NotFound();
            }
            return RedirectToAction(nameof(Index));
        }

        // GET: User/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null || _context.Users == null)
                return NotFound();

            var user = await _context.Users
                .FirstOrDefaultAsync(m => m.UserID == id);
            if (user == null) return NotFound();

            return View(user);
        }

        // POST: User/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            if (_context.Users == null)
                return Problem("Entity set 'UserDBContext.Users'  is null.");

            var user = await _context.Users.FindAsync(id);
            if (user != null)
                _context.Users.Remove(user);

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool UserExists(int id) =>
            _context.Users.Any(e => e.UserID == id);


        // POST: User/Connect/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Connect([Bind("UserID,Username,Password")] User user)
        {
            // fetch user from db
            User? dbUser = await _context.Users.FirstOrDefaultAsync(e => e.Username == user.Username);

            // if user doesnt exists return not found
            if (dbUser == null) return View(user);

            // does not match with password
            if (!BCrypt.Net.BCrypt.Verify(user.Password, dbUser.Password))
                return View(user);

            // jwt
            JwtSecurityToken token = _tokenService.Generate(user.Username);

            // save to cookie
            CookieOptions cookieOptions = new()
            {
                HttpOnly = true,
                Expires = token.ValidTo
            };
            Response.Cookies.Append(_config["JWT:CookieName"],
                new JwtSecurityTokenHandler().WriteToken(token),
                cookieOptions);

            return RedirectToAction(nameof(Index));
        }

        [AllowAnonymous]
        public IActionResult Connect() => View();

        public IActionResult Logout()
        {
            //Delete the Cookie from Browser.
            Response.Cookies.Delete(_config["JWT:CookieName"]);
            // redirect to login page
            return RedirectToAction(nameof(Connect));
        }
    }
}
