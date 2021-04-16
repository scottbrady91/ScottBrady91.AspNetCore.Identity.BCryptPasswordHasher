using System;

namespace ScottBrady91.AspNetCore.Identity
{
    /// <summary>
    /// Options for BCryptPasswordHasher.
    /// </summary>
    public class BCryptPasswordHasherOptions
    {
        /// <summary>
        /// The log2 of the number of rounds of hashing to apply. Defaults to 11
        /// </summary>
        public int WorkFactor { get; set; } = 11;
        
        /// <summary>
        /// Enables the use of SHA384 hashing prior to bcrypt hashing. This will make you vulnerable to password shucking. Defaults to false.
        /// https://www.scottbrady91.com/Authentication/Beware-of-Password-Shucking
        /// </summary>
        [Obsolete("Discouraged due to vulnerability to password shucking", false)]
        public bool EnhancedEntropy { get; set; } = false;
    }
}