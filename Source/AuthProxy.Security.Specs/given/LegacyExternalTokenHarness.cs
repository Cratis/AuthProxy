// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>A general JWT deployment that has not enabled tenant binding.</summary>
public class LegacyExternalTokenHarness : ExternalTokenBindingHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        base.AddSettings(settings);
        settings.Remove($"{C.Authentication.SectionKey}:ExternalTokenTenantBinding:Require");
        settings[$"{C.AuthProxy.SectionKey}:TenantResolutions:4:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.None);
    }
}
