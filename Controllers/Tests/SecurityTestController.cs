using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureApiDemo.Models;
using SecureApiDemo.Services;

namespace SecureApiDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityTestController : ControllerBase
    {
        private readonly ValidationService _validationService;
        private readonly PasswordHasher<IdentityUser> _passwordHasher;

        public SecurityTestController(ValidationService validationService)
        {
            _validationService = validationService;
            _passwordHasher = new PasswordHasher<IdentityUser>();
        }

        /// 1. Tests SQL Injection detection filters.
        /// Try: GET /api/securitytest/test-sqli?input=admin'--
        [HttpGet("test-sqli")]
        public IActionResult TestSqlInjection([FromQuery] string input = "' OR 1=1 --")
        {
            bool isClean = _validationService.IsValidInput(input);

            return Ok(new
            {
                Test = "SQL Injection Validation",
                Input = input,
                IsSecure = isClean,
                Result = isClean ? "PASS: Input is safe." : "BLOCKED: Potential SQL Injection detected!"
            });
        }

        /// 2. Tests Cross-Site Scripting (XSS) detection filters.
        /// Try: GET /api/securitytest/test-xss?input=<script>alert(1)</script>
        [HttpGet("test-xss")]
        public IActionResult TestXss([FromQuery] string input = "<script>alert('xss')</script>")
        {
            bool isClean = _validationService.IsValidXss(input);

            return Ok(new
            {
                Test = "XSS Validation",
                Input = input,
                IsSecure = isClean,
                Result = isClean ? "PASS: Input is safe." : "BLOCKED: Potential XSS attack detected!"
            });
        }


        /// 3. Tests Object Model validation checking both SQLi and XSS.
        /// Try: POST /api/securitytest/test-model
        [HttpPost("test-model")]
        public IActionResult TestObjectModel([FromBody] RegisterModel model)
        {
            bool isValid = _validationService.ValidateObjectModel(model, out string? flaggedProperty);

            if (!isValid)
            {
                return BadRequest(new
                {
                    Test = "Model Security Scan",
                    Status = "Failed",
                    FlaggedProperty = flaggedProperty,
                    Message = $"Security violation caught in property '{flaggedProperty}'."
                });
            }

            return Ok(new
            {
                Test = "Model Security Scan",
                Status = "Passed",
                Message = "Model input is completely clean from SQL Injection and XSS."
            });
        }

        /// 4. Tests ASP.NET Core built-in PBKDF2 Password Hashing & Verification.
        /// Try: GET /api/securitytest/test-hashing?password=SecretPassword123!
        [HttpGet("test-hashing")]
        public IActionResult TestPasswordHashing([FromQuery] string password = "SecretPassword123!")
        {
            var dummyUser = new IdentityUser { UserName = "testuser@example.com" };

            // Hash the password using ASP.NET Core Identity's hasher
            string hashedPassword = _passwordHasher.HashPassword(dummyUser, password);

            // Verify the correct password matches
            var verificationResult = _passwordHasher.VerifyHashedPassword(dummyUser, hashedPassword, password);
            bool isMatchSuccess = verificationResult == PasswordVerificationResult.Success;

            // Verify a wrong password fails
            var badVerificationResult = _passwordHasher.VerifyHashedPassword(dummyUser, hashedPassword, "WrongPassword!");
            bool isWrongPasswordBlocked = badVerificationResult == PasswordVerificationResult.Failed;

            return Ok(new
            {
                Test = "Password Hashing & Verification",
                OriginalPassword = password,
                HashedOutput = hashedPassword,
                CorrectPasswordVerified = isMatchSuccess,
                WrongPasswordCorrectlyRejected = isWrongPasswordBlocked,
                Result = (isMatchSuccess && isWrongPasswordBlocked) ? "PASS: Password hashing works securely." : "FAIL"
            });
        }
    }
}