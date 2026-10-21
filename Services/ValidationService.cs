using System.Text.RegularExpressions;

namespace SecureApiDemo.Services
{
    public class ValidationService
    {
        // Regex patterns commonly used in SQL injection attacks
        private static readonly string[] SqlInjectionPatterns = new[]
        {
            @"(%27)|(')",                    // Single quotes
            @"(%3D)|(=)",                    // Equals signs
            @"(%2D%2D)|(--)",              // SQL comments
            @"(%3B)|(;)",                    // Semicolons
            @"\b(OR|AND)\b\s+[\w\s]+\s*=\s*", // Tautologies like OR 1=1
            @"\bUNION\b\s+\bSELECT\b",       // UNION SELECT attacks
            @"\bDROP\b\s+\bTABLE\b",         // DROP TABLE commands
            @"\bEXEC(\s+|\()",               // EXEC commands
            @"\bCAST\s*\(",                  // CAST injections
            @"\bCONVERT\s*\("                // CONVERT injections
        };

        // Regex patterns for detecting potential Cross-Site Scripting (XSS) attacks
        private static readonly string[] XssPatterns = new[]
        {
            @"<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>", // Basic <script> tags
            @"javascript\s*:",                              // javascript: pseudo-protocol in href/src
            @"<\s*iframe[^>]*>",                            // <iframe> injections
            @"<\s*object[^>]*>",                            // <object> injections
            @"<\s*embed[^>]*>",                             // <embed> injections
            @"\bon\w+\s*=",                                 // Event handlers (e.g., onload=, onerror=, onclick=)
            @"<\s*img[^>]+src\s*=\s*['""]?\s*javascript\s*:", // JavaScript injected into image source
            @"expression\s*\(",                             // CSS expressions (IE based XSS)
            @"vbscript\s*:"                                 // VBScript pseudo-protocol
        };


        /// Checks if a given input string contains potential SQL injection patterns.
        public bool IsDangerousInput(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            foreach (var pattern in SqlInjectionPatterns)
            {
                if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }


        /// Sanitizes an input string by escaping or stripping potentially harmful characters.
        /// Note: EF Core parameterizes queries automatically, but this can be used as an extra security filter.
        public string SanitizeInput(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Remove common injection markers like comments and semicolons
            var sanitized = input.Replace("'", "''"); // Escape single quotes
            sanitized = Regex.Replace(sanitized, @"(--|;|/\*|\*/)", string.Empty);
            
            return sanitized;
        }


        /// Scans all string properties of an incoming object model for SQL injection patterns.
        public bool ValidateObjectModel<T>(T model, out string? flaggedProperty) where T : class
        {
            flaggedProperty = null;
            if (model == null) return true;

            var properties = typeof(T).GetProperties();
            foreach (var prop in properties)
            {
                if (prop.PropertyType == typeof(string))
                {
                    var value = prop.GetValue(model) as string;

                    if (IsDangerousInput(value))
                    {
                        flaggedProperty = prop.Name;
                        return false; // Found potential SQL injection
                    }

                    if (!IsValidXss(value))
                    {
                        flaggedProperty = prop.Name;
                        return false; // found XSS attack
                    }

                }
            }

            return true;
        }

        public bool IsValidInput(string input, string allowedSpecialCharacters = "")
        {
            if (string.IsNullOrEmpty(input))
                return false;

            var validCharacters = allowedSpecialCharacters.ToHashSet();

            return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
        }



        /// Validates whether a single input string is safe from Cross-Site Scripting (XSS) attacks.
        /// Returns true if safe (no malicious pattern found), false if dangerous.
        public bool IsValidXss(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return true;

            foreach (var pattern in XssPatterns)
            {
                if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                {
                    return false; // Malicious XSS pattern detected
                }
            }

            return true; // Input is clean from XSS
        }
    }    
}