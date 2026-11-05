// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Configures a partial signing block to test startup validation.</summary>
public class InvalidForwardedIdentityHarness : ForwardedIdentityHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        base.AddSettings(settings);
        settings.Remove($"{C.AuthProxy.SectionKey}:Services:app:ForwardedIdentity:SecretBase64");
    }
}
