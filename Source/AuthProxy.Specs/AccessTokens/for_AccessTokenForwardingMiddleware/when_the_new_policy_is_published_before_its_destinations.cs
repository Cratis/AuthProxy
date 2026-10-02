// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.ReverseProxy;
using Yarp.ReverseProxy.Model;

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenForwardingMiddleware;

public class when_the_new_policy_is_published_before_its_destinations : given.a_forwarding_middleware
{
    MicroserviceReverseProxyConfigProvider _provider;
    string _oldDestinationId;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["Reporting"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://old-backend/" },
                    AccessToken = new C.ServiceAccessToken { Scopes = ["old-audience"] },
                },
            },
        };
        Action<C.AuthProxy, string?> reload = null!;
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        monitor.OnChange(Arg.Do<Action<C.AuthProxy, string?>>(listener => reload = listener));
        _provider = new(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
        var oldCluster = _provider.GetConfig().Clusters.Single();
        _oldDestinationId = oldCluster.Destinations!.Single().Key;
        var oldDestination = new DestinationState(_oldDestinationId, new DestinationModel(oldCluster.Destinations.Single().Value));

        config.Services["Reporting"].Backend!.BaseUrl = "https://new-backend/";
        config.Services["Reporting"].AccessToken!.Scopes = ["new-audience"];
        reload(config, Options.DefaultName);
        var newCluster = _provider.GetConfig().Clusters.Single();

        // Freeze the snapshot at YARP's reload interval: the new Cluster.Model has been published,
        // but DestinationsState still holds the old origin. No timing or real reload race is needed.
        _accessToken = JsonSerializer.Deserialize<C.ServiceAccessToken>(newCluster.Metadata![MicroserviceReverseProxyConfigProvider.AccessTokenMetadataKey])!;
        _destinationBinding = newCluster.Metadata[MicroserviceReverseProxyConfigProvider.DestinationMetadataKey];
        _availableDestinations = [oldDestination];
        _allDestinations = [oldDestination];
    }

    Task Because() => Invoke();

    void Destroy() => _provider.Dispose();

    [Fact] void should_capture_a_different_binding() => (_destinationBinding != _oldDestinationId).ShouldBeTrue();
    [Fact] void should_refuse_the_mixed_snapshot() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_not_obtain_the_new_audiences_token() => _tokens.DidNotReceive().GetFor(Arg.Any<string>(), Arg.Any<C.ServiceAccessToken>(), Arg.Any<CancellationToken>());
    [Fact] void should_never_forward_to_the_old_backend() => _forwarded.ShouldBeFalse();
    [Fact] void should_not_replace_the_authorization_header() => _context.Request.Headers.Authorization.ToString().ShouldEqual("Bearer something-the-browser-sent");
}
