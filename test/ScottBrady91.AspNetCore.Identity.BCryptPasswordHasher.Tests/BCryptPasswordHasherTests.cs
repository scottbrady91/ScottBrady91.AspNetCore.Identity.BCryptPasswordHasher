using System;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Xunit;

namespace ScottBrady91.AspNetCore.Identity.BCryptPasswordHasher.Tests
{
    public class BCryptPasswordHasherTests
    {
        [Fact]
        public void HashPassword_WithDefaultSettings_ExpectVerifiableHash()
        {
            var password = Guid.NewGuid().ToString();

            var hasher = new BCryptPasswordHasher<string>();
            var hashedPassword = hasher.HashPassword("", password);

            BCrypt.Net.BCrypt.Verify(password, hashedPassword).Should().BeTrue();
        }
        
        [Fact]
        public void HashPassword_WithCustomWorkFactor_ExpectVerifiableHash()
        {
            var random = new Random();
            var password = Guid.NewGuid().ToString();

            var hasher = new BCryptPasswordHasher<string>(
                new OptionsWrapper<BCryptPasswordHasherOptions>(
                    new BCryptPasswordHasherOptions {WorkFactor = random.Next(8, 18)}));
            var hashedPassword = hasher.HashPassword("", password);

            BCrypt.Net.BCrypt.Verify(password, hashedPassword).Should().BeTrue();
        }

        [Fact]
        public void HashPassword_WithEnhancedEntropy_ExpectHashNotToVerify()
        {
            var password = Guid.NewGuid().ToString();

            var hasher = new BCryptPasswordHasher<string>(
                new OptionsWrapper<BCryptPasswordHasherOptions>(
                    new BCryptPasswordHasherOptions {EnhancedEntropy = true}));
            
            var hashedPassword = hasher.HashPassword("", password);

            BCrypt.Net.BCrypt.Verify(password, hashedPassword, true).Should().BeTrue();
            BCrypt.Net.BCrypt.EnhancedVerify(password, hashedPassword).Should().BeTrue();
        }

        [Fact]
        public void HashPassword_WithPasswordCreatedWithoutEnhancedEntropyButVerifiedWith_ExpectHashNotToVerify()
        {
            var password = Guid.NewGuid().ToString();

            var hasher = new BCryptPasswordHasher<string>(
                new OptionsWrapper<BCryptPasswordHasherOptions>(
                    new BCryptPasswordHasherOptions { EnhancedEntropy = false }));

            var hashedPassword = hasher.HashPassword("", password);

            BCrypt.Net.BCrypt.Verify(password, hashedPassword, true).Should().BeFalse();
            BCrypt.Net.BCrypt.EnhancedVerify(password, hashedPassword).Should().BeFalse();
        }

        [Fact]
        public void VerifyHashedPassword_WithDefaultSettings_ExpectSuccess()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

            var hasher = new BCryptPasswordHasher<string>();

            hasher.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Success);
        }

        [Fact]
        public void VerifyHashedPassword_WithEnhancedEntropy_ExpectSuccess()
        {
            var options = new BCryptPasswordHasherOptions {EnhancedEntropy = true};
            var password = Guid.NewGuid().ToString();
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password, options.WorkFactor, true);

            var hasher = new BCryptPasswordHasher<string>(new OptionsWrapper<BCryptPasswordHasherOptions>(options));

            hasher.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Success);
        }

        [Fact]
        public void VerifyHashedPassword_WhenPasswordCreatedWithEnhancedEntropyButVerifiedWithout_ExpectFailure()
        {
            var options = new BCryptPasswordHasherOptions { EnhancedEntropy = true };
            var password = Guid.NewGuid().ToString();
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password, options.WorkFactor);

            var hasher = new BCryptPasswordHasher<string>(new OptionsWrapper<BCryptPasswordHasherOptions>(options));

            hasher.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Failed);
        }
        
        [Fact]
        public void VerifyHashedPassword_WhenSuppliedPasswordDoesNotMatch_ExpectFailure()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString());

            var hasher = new BCryptPasswordHasher<string>();

            hasher.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Failed);
        }

        [Fact]
        public void VerifyHashedPassword_WhenCorrectV10Password_ExpectSuccess()
        {
            const string password = "6@JM}T-3DeZo&2i=U73A^nEY7tXe_3UC%RR";
            const string hashedPassword = "$2a$10$SpIhzEv3ATLa0CmTz4L7ouAn/w5NyedFic5X3fKaI9eu0xhW97OUC";

            var hasher = new BCryptPasswordHasher<string>();

            hasher.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Success);
        }
    }
}