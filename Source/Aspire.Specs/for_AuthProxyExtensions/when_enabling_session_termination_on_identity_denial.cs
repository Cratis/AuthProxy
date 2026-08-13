// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_enabling_session_termination_on_identity_denial : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithSessionTerminationOnIdentityDenial();
        _resource.WithSessionTerminationOnIdentityDenial();
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_enable_the_global_session_setting() =>
        _environment["Cratis__AuthProxy__Session__TerminateOnIdentityDenial"].ShouldEqual(bool.TrueString);

    [Fact] void should_not_create_a_per_service_setting() =>
        _environment.Keys.Any(_ => _.Contains("Services", StringComparison.Ordinal)).ShouldBeFalse();
}
