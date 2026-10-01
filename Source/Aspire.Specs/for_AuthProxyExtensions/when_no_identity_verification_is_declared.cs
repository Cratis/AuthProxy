// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

/// <summary>
/// The Aspire package states no default of its own for what a service's identity answer is worth: it writes
/// the setting only when asked. That is what keeps the two ends in step — an app host that never calls
/// <c language="text">WithIdentityVerification</c> gets AuthProxy's own default, which is the fail-closed
/// <see cref="IdentityVerificationMode.Required"/>, and one that wants enrichment only says
/// <see cref="IdentityVerificationMode.BestEffort"/> explicitly.
/// </summary>
public class when_no_identity_verification_is_declared : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithSessionTerminationOnIdentityDenial();

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_not_write_a_verification_mode() =>
        _environment.Keys.Any(_ => _.Contains("IdentityVerification", StringComparison.Ordinal)).ShouldBeFalse();
}
