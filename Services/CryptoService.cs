using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace SecureApiDemo.Services
{
    public class CryptoService
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public CryptoService(IOptions<CryptoOptions> options)
        {
            var key = options.Value.Key;
            var iv = options.Value.IV;

            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(iv))
                throw new ArgumentException("Key and IV must be provided.");

            _key = Encoding.UTF8.GetBytes(key);
            _iv = Encoding.UTF8.GetBytes(iv);
        }

        public string Encrypt(string plainText)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;

            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(plainText);
            }
            return Convert.ToBase64String(ms.ToArray());
        }

        public string Decrypt(string cipherText)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;

            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(Convert.FromBase64String(cipherText));
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }
    }


    public class CryptoOptions
    {
        public string Key { get; set; } = string.Empty;
        public string IV { get; set; } = string.Empty;
    }

}