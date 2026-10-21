using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureApiDemo.Models;
using SecureApiDemo.Services;

namespace SecureApiDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly TokenService _tokenService;
        private readonly CryptoService _cryptoService;
        private readonly ValidationService _validationService;

        public AuthController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            TokenService tokenService,
            CryptoService cryptoService,
            ValidationService validationService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _tokenService = tokenService;
            _cryptoService = cryptoService;
            _validationService = validationService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!_validationService.ValidateObjectModel(model, out var flaggedProperty))
            {
                return BadRequest(new { Message = $"Potential SQL Injection detected in property: {flaggedProperty}" });
            }

            var user = new IdentityUser { UserName = model.Email, Email = model.Email };
            
            var encryptedPassword = _cryptoService.Encrypt(model.Password);

            var result = await _userManager.CreateAsync(user, encryptedPassword);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            var roleToAssign = string.IsNullOrEmpty(model.Role) ? "User" : model.Role;
            if (!await _roleManager.RoleExistsAsync(roleToAssign))
            {
                await _roleManager.CreateAsync(new IdentityRole(roleToAssign));
            }

            await _userManager.AddToRoleAsync(user, roleToAssign);

            return Ok(new { Message = $"User registered successfully and assigned to role: {roleToAssign}" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            var encryptedPassword = _cryptoService.Encrypt(model.Password);

            if (user == null || !await _userManager.CheckPasswordAsync(user, encryptedPassword))
            {
                return Unauthorized(new { Message = "Invalid email or password." });
            }

            var roles = await _userManager.GetRolesAsync(user);
            var (token, expiration) = _tokenService.GenerateJwtToken(user, roles);

            return Ok(new AuthResponseModel
            {
                Token = token,
                Expiration = expiration
            });
        }
    }
}
