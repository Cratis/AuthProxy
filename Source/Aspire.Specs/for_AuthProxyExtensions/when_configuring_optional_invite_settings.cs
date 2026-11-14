// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_configuring_optional_invite_settings : given.an_auth_proxy_resource
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("configured-value")]
    public async Task should_omit_only_null_or_empty_settings(string? value)
    {
        _resource.WithInvite("spec-public-key", "https://backend.test/invites", value, value, value, value);

        var environment = await EnvironmentVariables();

        foreach (var setting in new[] { "Issuer", "Audience", "TenantClaim", "SubjectAlreadyExistsUrl" })
        {
            environment.TryGetValue($"Cratis__AuthProxy__Invite__{setting}", out var actual).ShouldEqual(!string.IsNullOrEmpty(value));
            actual.ShouldEqual(string.IsNullOrEmpty(value) ? null : value);
        }
        environment["Cratis__AuthProxy__Invite__PublicKeyPem"].ShouldEqual("spec-public-key");
        environment["Cratis__AuthProxy__Invite__ExchangeUrl"].ShouldEqual("https://backend.test/invites");
    }
}
