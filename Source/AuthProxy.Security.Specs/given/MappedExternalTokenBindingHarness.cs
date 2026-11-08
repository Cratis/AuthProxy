// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>A general JWT deployment mapping external tenant identifiers explicitly.</summary>
public class MappedExternalTokenBindingHarness : ExternalTokenBindingHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        base.AddSettings(settings);
        settings[$"{C.Authentication.SectionKey}:ExternalTokenTenantBinding:TenantMapping:external-a"] = "tenant-a";
    }
}
