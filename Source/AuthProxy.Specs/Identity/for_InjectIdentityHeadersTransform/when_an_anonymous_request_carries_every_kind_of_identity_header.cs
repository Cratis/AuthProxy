// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity.for_InjectIdentityHeadersTransform;

/// <summary>
/// An anonymous request has no identity of its own to forward, so nothing the caller claims about identity,
/// tenant, an on-behalf session or a signature may reach the backend, however many times or in whatever case
/// the caller wrote it.
/// </summary>
public class when_an_anonymous_request_carries_every_kind_of_identity_header : Specification
{
    static readonly string[] _hostile =
    [
        Headers.Principal,
        Headers.PrincipalId.ToUpperInvariant(),
        "x_ms_client_principal_idp",
        Headers.TenantId,
        Headers.LegacyTenantId,
        Headers.TokenClientId,
        Headers.TokenScope,
        Headers.OnBehalfActor,
        Headers.OnBehalfAssertion,
        "X-Cratis-On-Behalf-Anything",
        Headers.ForwardedIdentitySignature,
        "x-cratis-forwarded-identity-version",
        "x-cratis-credential-kind",
        "x-cratis-subject",
        "x-cratis-sender-binding"
    ];

    RequestTransformContext _context;

    void Establish()
    {
        _context = new RequestTransformContext
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity()) },
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://service.local/public")
        };

        foreach (var name in _hostile)
        {
            _context.ProxyRequest.Headers.TryAddWithoutValidation(name, ["caller-one", "caller-two"]);
        }

        _context.ProxyRequest.Headers.TryAddWithoutValidation("Accept", "application/json");
    }

    Task Because() => new InjectIdentityHeadersTransform().ApplyAsync(_context).AsTask();

    [Fact] void should_forward_none_of_the_hostile_headers() => _hostile.Where(_context.ProxyRequest.Headers.Contains).ShouldBeEmpty();

    [Fact] void should_forward_no_header_under_a_reserved_prefix() => ReservedHeaders().ShouldBeEmpty();

    [Fact] void should_keep_an_ordinary_header() => _context.ProxyRequest.Headers.GetValues("Accept").Single().ShouldEqual("application/json");

    IEnumerable<string> ReservedHeaders() =>
        _context.ProxyRequest.Headers
            .Select(header => header.Key.Replace('_', '-'))
            .Where(name => name.StartsWith("x-ms-client-principal", StringComparison.OrdinalIgnoreCase)
                || name.StartsWith("x-cratis-on-behalf", StringComparison.OrdinalIgnoreCase)
                || name.StartsWith("x-cratis-forwarded-identity", StringComparison.OrdinalIgnoreCase));
}
