// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Keeps service signing enabled while leaving the tenant-list flow in legacy mode.</summary>
public class UnsignedTenantForwardedIdentityHarness : ForwardedIdentityHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        base.AddSettings(settings);
        const string path = $"{C.AuthProxy.SectionKey}:TenantResolutions:1:Options";
        settings[$"{path}:TenantsEndpoint"] = Origin.BaseUrl + "/tenants";
        settings.Remove($"{path}:ForwardedIdentity:Audience");
        settings.Remove($"{path}:ForwardedIdentity:KeyId");
        settings.Remove($"{path}:ForwardedIdentity:SecretBase64");
    }
}
