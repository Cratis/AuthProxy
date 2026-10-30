// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_turning_off_the_identity_details_cookie : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithoutIdentityDetailsCookie();
        _resource.WithoutIdentityDetailsCookie();
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact]
    void should_turn_off_the_global_session_setting() =>
        _environment["Cratis__AuthProxy__Session__EmitIdentityDetailsCookie"].ShouldEqual(bool.FalseString);

    [Fact]
    void should_not_create_a_per_service_setting() =>
        _environment.Keys.Any(_ => _.Contains("Services", StringComparison.Ordinal)).ShouldBeFalse();
}
