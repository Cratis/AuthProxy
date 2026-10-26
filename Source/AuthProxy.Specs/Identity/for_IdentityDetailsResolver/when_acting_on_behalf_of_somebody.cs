// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;
using Cratis.AuthProxy.OnBehalfSessions;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

/// <summary>
/// During an on-behalf session the identity being resolved is the represented user's. It is only sent to the services
/// the session may reach, and no remembered result is used or left behind.
/// </summary>
public class when_acting_on_behalf_of_somebody : Specification
{
    OnBehalfConfiguration _configuration;
    RespondingHttpMessageHandler _handler;
    IMemoryCache _memoryCache;
    IdentityDetailsResolver _resolver;
    DefaultHttpContext _context;
    IdentityProviderResult _result;

    void Establish()
    {
        _configuration = new();
        _configuration.Value.Services[OnBehalfConfiguration.ServiceName].IdentityVerification = C.IdentityVerificationMode.BestEffort;
        _configuration.Value.Services["billing"] = new()
        {
            Backend = new() { BaseUrl = "https://billing.internal" },
            IdentityVerification = C.IdentityVerificationMode.BestEffort,
        };
        _configuration.Value.Session.IdentityResultCacheDuration = TimeSpan.FromMinutes(5);

        _handler = new(HttpStatusCode.OK, /*lang=json,strict*/ "{\"isAuthenticated\":true,\"isAuthorized\":true,\"details\":{}}");
        _memoryCache = Substitute.For<IMemoryCache>();
        _resolver = new IdentityDetailsResolver(
            _configuration.Monitor,
            _handler.AsFactory(),
            [],
            _memoryCache,
            Substitute.For<IIdentityAuthorizationCache>(),
            Substitute.For<ILogger<IdentityDetailsResolver>>());

        _context = new DefaultHttpContext { User = Sessions.ActorPrincipal() };
        _context.SetOnBehalf(new OnBehalfContext(Sessions.At(DateTimeOffset.UtcNow), Sessions.Represented(), "actor", "assertion"));
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Sessions.Represented(), Sessions.Tenant);

    [Fact] void should_be_authorized() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_only_ask_the_granting_service() => _handler.RequestedUris.Select(_ => _.Host).ShouldContainOnly("portal.internal");
    [Fact] void should_not_use_a_remembered_result() => _memoryCache.DidNotReceive().TryGetValue(Arg.Any<object>(), out Arg.Any<object?>());
    [Fact] void should_not_remember_the_result() => _memoryCache.DidNotReceive().CreateEntry(Arg.Any<object>());
}
