// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfForwardTransform;

/// <summary>
/// The assertion binds the request it travels with: the service, the method and the path the backend receives — below
/// the destination's own base path and after the service's prefix was stripped — and the exact identity headers.
/// </summary>
public class when_forwarding_a_session_request : Specification
{
    const string ActorHeader = "YWN0b3I=";

    OnBehalfConfiguration _configuration;
    RequestTransformContext _transformContext;
    OnBehalfSession _session;
    JsonWebToken _assertion;
    TokenValidationResult _validation;

    void Establish()
    {
        _configuration = new();
        var now = DateTimeOffset.FromUnixTimeSeconds(TimeProvider.System.GetUtcNow().ToUnixTimeSeconds());
        _session = Sessions.At(now);
        var httpContext = new DefaultHttpContext { User = Sessions.ActorPrincipal() };
        httpContext.Request.Method = HttpMethods.Post;
        httpContext.SetOnBehalf(new OnBehalfContext(_session, Sessions.Represented(), ActorHeader, new OnBehalfAttestations(_configuration.Monitor, new ManualTime(now))));

        var route = new RouteConfig
        {
            RouteId = "portal-route",
            ClusterId = "portal-backend-cluster",
            Metadata = new Dictionary<string, string> { [ServiceSelection.RouteMetadataKey] = OnBehalfConfiguration.ServiceName },
        };
        httpContext.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(new RouteModel(route, new ClusterState(route.ClusterId), HttpTransformer.Default)), "proxied"));

        _transformContext = new RequestTransformContext
        {
            HttpContext = httpContext,
            ProxyRequest = new HttpRequestMessage(HttpMethod.Post, (Uri?)null),
            DestinationPrefix = "https://portal.internal/base/",
            Path = "/orders/42",
        };
        _transformContext.ProxyRequest.SetMicrosoftIdentityHeaders(Sessions.Represented());
        _transformContext.ProxyRequest.Headers.Authorization = new("Bearer", "actors-own-token");
    }

    async Task Because()
    {
        await new OnBehalfForwardTransform().ApplyAsync(_transformContext);
        var token = _transformContext.ProxyRequest.Headers.GetValues(Headers.OnBehalfAssertion).Single();
        _assertion = new JsonWebTokenHandler().ReadJsonWebToken(token);
        _validation = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKey = _configuration.ValidationKey,
            ValidIssuer = OnBehalfConfiguration.Issuer,
            ValidAudience = OnBehalfConfiguration.Audience,
        });
    }

    string Claim(string type) => _assertion.Claims.Single(_ => _.Type == type).Value;

    [Fact] void should_forward_a_valid_assertion() => _validation.IsValid.ShouldBeTrue();
    [Fact] void should_forward_the_actor() => _transformContext.ProxyRequest.Headers.GetValues(Headers.OnBehalfActor).Single().ShouldEqual(ActorHeader);
    [Fact] void should_bind_the_method() => Claim(OnBehalfAttestationClaims.HttpMethod).ShouldEqual("POST");
    [Fact] void should_bind_the_path_the_backend_receives() => Claim(OnBehalfAttestationClaims.HttpUri).ShouldEqual("/base/orders/42");
    [Fact] void should_bind_the_service() => Claim(OnBehalfAttestationClaims.Service).ShouldEqual(OnBehalfConfiguration.ServiceName);
    [Fact] void should_bind_the_session() => Claim(OnBehalfAttestationClaims.SessionId).ShouldEqual(_session.SessionId);
    [Fact] void should_bind_the_principal_header_it_travels_with() =>
        Claim(OnBehalfAttestationClaims.PrincipalHash).ShouldEqual(Base64UrlEncoder.Encode(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes(Sessions.Represented().ToBase64()))));
    [Fact] void should_not_forward_any_credential_of_the_actors() => _transformContext.ProxyRequest.Headers.Authorization.ShouldBeNull();
}
