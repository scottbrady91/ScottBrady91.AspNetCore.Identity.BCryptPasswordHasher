using System;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Xunit;
#pragma warning disable 618

namespace ScottBrady91.AspNetCore.Identity.BCryptPasswordHasher.Tests
{
    public class BCryptPasswordHasherTests
    {
        private BCryptPasswordHasherOptions options = new BCryptPasswordHasherOptions();
        
        private BCryptPasswordHasher<string> CreateSut() =>
            new BCryptPasswordHasher<string>(
                options != null ? new OptionsWrapper<BCryptPasswordHasherOptions>(options) : null);

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void HashPassword_WhenPasswordIsNullOrWhitespace_ExpectArgumentNullException(string password)
        {
            var sut = CreateSut();
            Assert.Throws<ArgumentNullException>(() => sut.HashPassword(null, password));
        }
        
        [Fact]
        public void HashPassword_WithDefaultSettings_ExpectVerifiableHash()
        {
            var password = Guid.NewGuid().ToString();

            var sut = CreateSut();
            var hashedPassword = sut.HashPassword("", password);

            BCrypt.Net.BCrypt.Verify(password, hashedPassword).Should().BeTrue();
        }

        [Fact]
        public void HashPassword_WhenCalledMultipleTimesWithSamePlaintext_ExpectDifferentHash()
        {
            var password = Guid.NewGuid().ToString();

            var sut = CreateSut();
            var hashedPassword1 = sut.HashPassword("", password);
            var hashedPassword2 = sut.HashPassword("", password);

            hashedPassword1.Should().NotBe(hashedPassword2);
        }
        
        [Fact]
        public void HashPassword_WithCustomWorkFactor_ExpectVerifiableHash()
        {
            var password = Guid.NewGuid().ToString();

            options.WorkFactor = options.WorkFactor - 1;
            var sut = CreateSut();

            var hashedPassword = sut.HashPassword("", password);

            BCrypt.Net.BCrypt.Verify(password, hashedPassword).Should().BeTrue();
        }

        [Fact]
        public void HashPassword_WithEnhancedEntropy_ExpectHashNotToVerify()
        {
            var password = Guid.NewGuid().ToString();

            options.EnhancedEntropy = true;
            var sut = CreateSut();
            
            var hashedPassword = sut.HashPassword("", password);

            BCrypt.Net.BCrypt.Verify(password, hashedPassword, true).Should().BeTrue();
            BCrypt.Net.BCrypt.EnhancedVerify(password, hashedPassword).Should().BeTrue();
        }

        [Fact]
        public void HashPassword_WithPasswordCreatedWithoutEnhancedEntropyButVerifiedWith_ExpectHashNotToVerify()
        {
            var password = Guid.NewGuid().ToString();

            options.EnhancedEntropy = false;
            var sut = CreateSut();

            var hashedPassword = sut.HashPassword("", password);

            BCrypt.Net.BCrypt.Verify(password, hashedPassword, true).Should().BeFalse();
            BCrypt.Net.BCrypt.EnhancedVerify(password, hashedPassword).Should().BeFalse();
        }
        
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void VerifyHashedPassword_WhenHashedPasswordIsNullOrWhitespace_ExpectArgumentNullException(string hashedPassword)
        {
            var sut = CreateSut();
            Assert.Throws<ArgumentNullException>(() => sut.VerifyHashedPassword(null, hashedPassword, Guid.NewGuid().ToString()));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void VerifyHashedPassword_WhenPasswordIsNullOrWhitespace_ExpectArgumentNullException(string password)
        {
            var sut = CreateSut();
            Assert.Throws<ArgumentNullException>(() => sut.VerifyHashedPassword(null, Guid.NewGuid().ToString(), password));
        }

        [Fact]
        public void VerifyHashedPassword_WithDefaultSettings_ExpectSuccess()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

            var sut = CreateSut();

            sut.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Success);
        }

        [Fact]
        public void VerifyHashedPassword_WithEnhancedEntropy_ExpectSuccess()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password, options.WorkFactor, true);

            options.EnhancedEntropy = true;
            var sut = CreateSut();

            sut.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Success);
        }

        [Fact]
        public void VerifyHashedPassword_WhenPasswordCreatedWithEnhancedEntropyButVerifiedWithout_ExpectFailure()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password, options.WorkFactor, false);

            options.EnhancedEntropy = true;
            var sut = CreateSut();

            sut.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Failed);
        }
        
        [Fact]
        public void VerifyHashedPassword_WhenSuppliedPasswordDoesNotMatch_ExpectFailure()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString());

            var sut = CreateSut();

            sut.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.Failed);
        }

        [Fact]
        public void VerifyHashedPassword_WhenCorrectV10Password_ExpectSuccessRehashNeeded()
        {
            const string password = "6@JM}T-3DeZo&2i=U73A^nEY7tXe_3UC%RR";
            const string hashedPassword = "$2a$10$SpIhzEv3ATLa0CmTz4L7ouAn/w5NyedFic5X3fKaI9eu0xhW97OUC";

            var sut = CreateSut();

            sut.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
        }

        [Fact]
        public void VerifyHashedPassword_WhenPasswordHashedWithLowerEntropy_ExpectSuccessRehashNeeded()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password, 10);

            options.WorkFactor = 11;
            var sut = CreateSut();

            sut.VerifyHashedPassword("", hashedPassword, password).Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
        }
    }
}