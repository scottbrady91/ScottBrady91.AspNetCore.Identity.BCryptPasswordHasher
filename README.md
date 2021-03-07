# BCrypt Password Hasher for ASP.NET Core Identity (ASP.NET Identity 3)

[![NuGet](https://img.shields.io/nuget/v/ScottBrady91.AspNetCore.Identity.BCryptPasswordHasher.svg)](https://www.nuget.org/packages/ScottBrady91.AspNetCore.Identity.BCryptPasswordHasher/)

An implementation of IPasswordHasher<TUser> using [BCrypt.NET - next](https://github.com/BcryptNet/bcrypt.net).

## Installation

```
services.AddIdentity<TUser, TRole>();
services.AddScoped<IPasswordHasher<TUser>, BCryptPasswordHasher<TUser>>();
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

## .NET Support

This library supports Current and LTS versions of .NET.
