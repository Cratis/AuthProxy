// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// The mode belongs to the service, not to the deployment. A reporting or search service that only ever
/// contributed display details is not made into a gate by a sibling service becoming one — its outage still
/// costs the caller nothing but the details it would have supplied.
/// <para>
/// This is the property that makes the setting adoptable at all: a deployment can require verification of
/// the one service that actually answers with a verdict without turning every other backend into a single
/// point of failure.
/// </para>
/// </summary>
public class and_a_best_effort_service_cannot_be_reached : given.a_required_verification_resolver
{
    const string EnrichingHost = "enrichment.example.com";

    IdentityProviderResult _result;

    void Establish()
    {
        _config.Services["enrichment"] = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = $"https://{EnrichingHost}" }
        };
        _handler.Respond = (request, _, _) => request.RequestUri!.Host == EnrichingHost
            ? throw new HttpRequestException("connection refused")
            : Task.FromResult(Response(HttpStatusCode.OK, PositiveBody));
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_be_authorized() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_record_the_authorization() => _authorizationCache.Received(1).Record(_context, Arg.Any<ClientPrincipal>(), TenantId);
    [Fact] void should_not_clear_the_authorization() => _authorizationCache.DidNotReceive().Clear(Arg.Any<HttpContext>());
}
