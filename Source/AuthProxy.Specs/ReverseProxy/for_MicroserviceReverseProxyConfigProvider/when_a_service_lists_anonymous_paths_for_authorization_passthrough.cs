// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

public class when_a_service_lists_anonymous_paths_for_authorization_passthrough : Specification
{
    Yarp.ReverseProxy.Configuration.IProxyConfig _config;

    void Establish()
    {
        var authProxy = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["App"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/" },
                    AnonymousPaths = ["/hooks", "/hooks/other", "/public"],
                    PassCallerAuthorizationPaths = ["/HOOKS/", "/hooks/deeper", "/missing"]
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);
        _config = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>()).GetConfig();
    }

    bool Passes(string path) =>
        _config.Routes.Single(_ => _.Match.Path == $"{path}/{{**catch-all}}").Metadata!.ContainsKey(AnonymousPaths.PassCallerAuthorizationMetadataKey);

    [Fact] void should_mark_the_listed_route_whatever_its_case() => Passes("/hooks").ShouldBeTrue();
    [Fact] void should_not_mark_a_nested_anonymous_route_that_is_not_listed() => Passes("/hooks/other").ShouldBeFalse();
    [Fact] void should_not_mark_an_anonymous_route_that_is_not_listed() => Passes("/public").ShouldBeFalse();
    [Fact] void should_not_create_a_route_for_a_listed_path_that_is_not_anonymous() =>
        _config.Routes.Any(_ => _.Match.Path!.StartsWith("/hooks/deeper", StringComparison.OrdinalIgnoreCase) || _.Match.Path.StartsWith("/missing", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
    [Fact] void should_not_mark_any_authenticated_route() =>
        _config.Routes.Any(_ => _.AuthorizationPolicy != "anonymous" && _.Metadata!.ContainsKey(AnonymousPaths.PassCallerAuthorizationMetadataKey)).ShouldBeFalse();
}
