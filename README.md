# BCrypt Password Hasher for ASP.NET Core Identity

[![NuGet](https://img.shields.io/nuget/v/ScottBrady91.AspNetCore.Identity.BCryptPasswordHasher.svg)](https://www.nuget.org/packages/ScottBrady91.AspNetCore.Identity.BCryptPasswordHasher/)

An implementation of `IPasswordHasher<TUser>` using [BCrypt.NET - next](https://github.com/BcryptNet/bcrypt.net).

## Installation

```csharp
services.AddIdentity<TUser, TRole>();
services.AddScoped<IPasswordHasher<TUser>, BCryptPasswordHasher<TUser>>();
```

### Options

- **WorkFactor**: int
- **EnhancedEntropy**: bool *(Obsolete due to [password shucking](https://www.scottbrady91.com/Authentication/Beware-of-Password-Shucking) vulnerability)*

Register with:

```csharp
services.Configure<BCryptPasswordHasherOptions>(options => {
    options.WorkFactor = 11;
    options.EnhancedEntropy = false;
});
```

## .NET Support

This library supports Current and LTS versions of .NET.
