using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SecureApiDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DataController : ControllerBase
    {
        [HttpGet("public-data")]
        [Authorize]
        public IActionResult GetPublicData()
        {
            return Ok(new { Message = "Hello! You are authenticated." });
        }

        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAdminData()
        {
            return Ok(new { Message = "Welcome Admin! High-privilege access granted." });
        }

        [HttpGet("user-or-admin")]
        [Authorize(Roles = "Admin,User")]
        public IActionResult GetUserData()
        {
            return Ok(new { Message = "Welcome Standard User or Admin." });
        }

        [HttpGet("special-resource")]
        [Authorize(Policy = "MinimumGuestOrAbove")]
        public IActionResult GetSpecialResource()
        {
            return Ok(new { Message = "Access granted via Policy: MinimumGuestOrAbove." });
        }
    }
}
