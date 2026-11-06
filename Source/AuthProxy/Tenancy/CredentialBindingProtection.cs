// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>Isolates AuthProxy-protected credentials by the configured deployment binding.</summary>
public static class CredentialBindingProtection
{
    /// <summary>Gets the data-protection application name, preserving the legacy name until binding is configured.</summary>
    /// <param name="configuration">The deployment configuration.</param>
    /// <returns>The binding-specific application name.</returns>
    public static string ApplicationName(IConfiguration configuration)
    {
        var binding = configuration.GetSection($"{C.AuthProxy.SectionKey}:CredentialBinding").Get<C.CredentialBinding>() ?? new();
        var name = "Cratis.AuthProxy";
        if (binding.Resource.Length > 0) name += $";resource={binding.Resource}";
        if (binding.Environment.Length > 0) name += $";environment={binding.Environment}";
        return name;
    }
}
