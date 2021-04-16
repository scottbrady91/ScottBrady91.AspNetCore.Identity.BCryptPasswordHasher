using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace ScottBrady91.AspNetCore.Identity
{
    /// <summary>
    /// ASP.NET Core Identity password hasher using the bcrypt password hashing algorithm.
    /// </summary>
    /// <typeparam name="TUser">your ASP.NET Core Identity user type (e.g. IdentityUser). User is not used by this implementation</typeparam>
    public class BCryptPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
    {
        private readonly BCryptPasswordHasherOptions options;

        /// <summary>
        /// Creates a new BCryptPasswordHasher.
        /// </summary>
        /// <param name="optionsAccessor">optional BCryptPasswordHasherOptions</param>
        public BCryptPasswordHasher(IOptions<BCryptPasswordHasherOptions> optionsAccessor = null)
        {
            options = optionsAccessor?.Value ?? new BCryptPasswordHasherOptions();
        }

        /// <summary>
        /// Hashes a password using bcrypt.
        /// </summary>
        /// <param name="user">not used for this implementation</param>
        /// <param name="password">plaintext password</param>
        /// <returns>hashed password</returns>
        /// <exception cref="ArgumentNullException">missing plaintext password</exception>
        public virtual string HashPassword(TUser user, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));

#pragma warning disable 618
            return BCrypt.Net.BCrypt.HashPassword(password, options.WorkFactor, options.EnhancedEntropy);
#pragma warning restore 618
        }

        /// <summary>
        /// Verifies a plaintext password against a stored hash.
        /// </summary>
        /// <param name="user">not used for this implementation</param>
        /// <param name="hashedPassword">the stored, hashed password</param>
        /// <param name="providedPassword">the plaintext password to verify against the stored hash</param>
        /// <returns>If the password matches the stored password. Returns SuccessRehashNeeded if the work factor has changed</returns>
        /// <exception cref="ArgumentNullException">missing plaintext password or hashed password</exception>
        public virtual PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
        {
            if (string.IsNullOrWhiteSpace(hashedPassword)) throw new ArgumentNullException(nameof(hashedPassword));
            if (string.IsNullOrWhiteSpace(providedPassword)) throw new ArgumentNullException(nameof(providedPassword));

#pragma warning disable 618
            var isValid = BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword, options.EnhancedEntropy);
#pragma warning restore 618

            if (isValid && BCrypt.Net.BCrypt.PasswordNeedsRehash(hashedPassword, options.WorkFactor))
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }

            return isValid ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
    }
}
