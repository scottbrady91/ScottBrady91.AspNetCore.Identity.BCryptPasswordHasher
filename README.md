# bcrypt Password Hasher for ASP.NET Core Identity (ASP.NET Identity 3)

[![NuGet](https://img.shields.io/nuget/v/ScottBrady91.AspNetCore.Identity.BCryptPasswordHasher.svg)]()

An implementation of IPasswordHasher<TUser> using [BCrypt.NET - next](https://github.com/BcryptNet/bcrypt.net).

## Installation

```
services.AddScoped<IPasswordHasher<ApplicationUser>, BCryptPasswordHasher<ApplicationUser>>();
```

### Options

 - **WorkFactor**: int
 - **EnhancedEntropy**: bool

Register with:
```
services.Configure<BCryptPasswordHasherOptions>(options => {
	options.WorkFactor = 10;
	options.EnhancedEntropy = false;
});
```
