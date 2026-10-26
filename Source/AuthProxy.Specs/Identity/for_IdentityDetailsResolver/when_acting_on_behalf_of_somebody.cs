// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;
using Cratis.AuthProxy.OnBehalfSessions;
using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

/// <summary>
/// During an on-behalf session the identity being resolved is the represented user's. It is only sent to the services
/// the session may reach, it carries the actor and an assertion bound to the call exactly as a forwarded request does,
/// and no remembered result is used or left behind.
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
        _context.SetOnBehalf(new OnBehalfContext(Sessions.At(DateTimeOffset.UtcNow), Sessions.Represented(), "actor", new OnBehalfAttestations(_configuration.Monitor, TimeProvider.System)));
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Sessions.Represented(), Sessions.Tenant);

    [Fact] void should_be_authorized() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_only_ask_the_granting_service() => _handler.RequestedUris.Select(_ => _.Host).ShouldContainOnly("portal.internal");
    [Fact] void should_name_the_actor() => _handler.LastHeaders[Headers.OnBehalfActor].ShouldEqual("actor");
    [Fact] void should_bind_the_assertion_to_the_identity_endpoint() => Claim(OnBehalfAttestationClaims.HttpUri).ShouldEqual(WellKnownPaths.IdentityDetails);
    [Fact] void should_bind_the_assertion_to_the_method() => Claim(OnBehalfAttestationClaims.HttpMethod).ShouldEqual("GET");
    [Fact] void should_bind_the_assertion_to_the_service() => Claim(OnBehalfAttestationClaims.Service).ShouldEqual(OnBehalfConfiguration.ServiceName);
    [Fact] void should_bind_the_assertion_to_the_forwarded_purpose() => Claim(OnBehalfAttestationClaims.Purpose).ShouldEqual(OnBehalfAttestationClaims.ForwardPurpose);
    [Fact] void should_not_use_a_remembered_result() => _memoryCache.DidNotReceive().TryGetValue(Arg.Any<object>(), out Arg.Any<object?>());
    [Fact] void should_not_remember_the_result() => _memoryCache.DidNotReceive().CreateEntry(Arg.Any<object>());

    string Claim(string type) =>
        new JsonWebTokenHandler().ReadJsonWebToken(_handler.LastHeaders[Headers.OnBehalfAssertion]).Claims.Single(_ => _.Type == type).Value;
}
