namespace SecureApiDemo.Models
{
    public class RegisterModel
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Role { get; set; } = "User"; // Options: Admin, User, Guest
    }

    public class LoginModel
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class AuthResponseModel
    {
        public string Token { get; set; } = string.Empty;
        public DateTime Expiration { get; set; }
    }
}
