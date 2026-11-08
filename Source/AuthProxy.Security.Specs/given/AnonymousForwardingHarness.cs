// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>A tenant-bound bearer deployment with signed forwarding and an anonymous route.</summary>
public class AnonymousForwardingHarness : ExternalTokenBindingHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        base.AddSettings(settings);
        const string root = C.AuthProxy.SectionKey;
        settings[$"{root}:Profile"] = nameof(C.DeploymentProfile.LocalDevelopment);
        settings[$"{root}:Services:app:AnonymousPaths:0"] = "/public";
        settings[$"{root}:Services:declaration:AnonymousPaths:0"] = "/declared-public";
        settings[$"{root}:Services:app:Default"] = "true";
        settings[$"{root}:Services:app:ForwardedIdentity:Audience"] = "anonymous-forwarding-spec";
        settings[$"{root}:Services:app:ForwardedIdentity:KeyId"] = "spec-key";
        settings[$"{root}:Services:app:ForwardedIdentity:SecretBase64"] = Convert.ToBase64String(new byte[32]);
    }
}
