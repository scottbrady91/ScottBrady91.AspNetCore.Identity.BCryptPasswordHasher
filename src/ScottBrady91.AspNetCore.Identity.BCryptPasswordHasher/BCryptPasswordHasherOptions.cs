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
        /// Enables the use of SHA384 hashing prior to bcrypt hashing. Defaults to false
        /// </summary>
        public bool EnhancedEntropy { get; set; } = false;
    }
}