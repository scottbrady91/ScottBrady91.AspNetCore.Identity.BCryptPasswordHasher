using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace ScottBrady91.AspNetCore.Identity
{
    public class BCryptPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
    {
        private readonly BCryptPasswordHasherOptions options;

        public BCryptPasswordHasher(IOptions<BCryptPasswordHasherOptions> optionsAccessor = null)
        {
            options = optionsAccessor?.Value ?? new BCryptPasswordHasherOptions();
        }

        public virtual string HashPassword(TUser user, string password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));

            return BCrypt.Net.BCrypt.HashPassword(password, options.WorkFactor, options.EnhancedEntropy);
        }

        public virtual PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
        {
            if (hashedPassword == null) throw new ArgumentNullException(nameof(hashedPassword));
            if (providedPassword == null) throw new ArgumentNullException(nameof(providedPassword));

            var isValid = BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword, options.EnhancedEntropy);

            return isValid ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }
}
