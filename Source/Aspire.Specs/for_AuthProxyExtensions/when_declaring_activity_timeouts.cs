// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_declaring_activity_timeouts : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithActivityTimeout(TimeSpan.FromMinutes(30));
        _resource.WithServiceActivityTimeout("streams", TimeSpan.FromHours(2));
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_declare_the_global_timeout() => _environment["Cratis__AuthProxy__ActivityTimeout"].ShouldEqual("00:30:00");
    [Fact] void should_declare_the_service_timeout() => _environment["Cratis__AuthProxy__Services__streams__ActivityTimeout"].ShouldEqual("02:00:00");
}
