namespace ScottBrady91.AspNetCore.Identity
{
    public class BCryptPasswordHasherOptions
    {
        public int WorkFactor { get; set; } = 10;
        public bool EnhancedEntropy { get; set; } = false;
    }
}