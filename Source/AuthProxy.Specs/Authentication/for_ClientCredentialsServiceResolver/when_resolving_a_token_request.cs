// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsServiceResolver;

public class when_resolving_a_token_request : Specification
{
    const string Unavailable = "The requested service is not available for client credentials.";
    const string Ambiguous = "Multiple services are configured for client credentials. Specify the 'service' form field.";

    [Theory]
    [InlineData(0, null, false, Unavailable)]
    [InlineData(0, "main", false, Unavailable)]
    [InlineData(1, null, true, "")]
    [InlineData(1, " ", true, "")]
    [InlineData(1, "MAIN", true, "")]
    [InlineData(1, "missing", false, Unavailable)]
    [InlineData(2, null, false, Ambiguous)]
    [InlineData(2, " ", false, Ambiguous)]
    [InlineData(2, "main", true, "")]
    [InlineData(2, "missing", false, Unavailable)]
    public void should_preserve_service_selection_and_error_messages(int serviceCount, string? name, bool expected, string error)
    {
        var configuration = new C.AuthProxy();
        if (serviceCount > 0) configuration.Services["main"] = CreateService();
        if (serviceCount > 1) configuration.Services["other"] = CreateService();
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(configuration);
        var resolver = new ClientCredentialsServiceResolver(monitor, Substitute.For<ILogger<ClientCredentialsServiceResolver>>());

        resolver.TryResolveForTokenRequest(name, out var service, out var description).ShouldEqual(expected);

        description.ShouldEqual(error);
        if (expected) service.Name.ShouldEqual("main");
        else service.ShouldBeNull();
    }

    static C.Service CreateService() => new()
    {
        Backend = new() { BaseUrl = "https://backend.test/" },
        ClientCredentials = new()
    };
}
