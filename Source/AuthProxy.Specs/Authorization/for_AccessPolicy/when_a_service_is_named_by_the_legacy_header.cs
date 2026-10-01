// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// A client that still names its service in the legacy <c language="text">Service-ID</c> header is routed to that service, so
/// that service's requirements have to apply to it too — otherwise renaming the header would be a way around
/// a requirement. When both headers are sent the current <c language="text">x-cratis-microservice</c> wins, which is the one
/// the route table matches on.
/// </summary>
public class when_a_service_is_named_by_the_legacy_header : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _legacyOnly;
    AccessDecision _bothNamingDifferentServices;

    void Establish() => _config = new C.AuthProxy
    {
        Services = new Dictionary<string, C.Service>
        {
            ["admin"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "http://admin.test/" },
                Authorization = new C.Authorization { RequiredClaims = [Claiming("urn:github:team", "Cratis/operations")] },
            },
            ["portal"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "http://portal.test/" },
            },
        },
    };

    void Because()
    {
        CallerCarrying(new Claim("urn:github:organization", "Cratis"));

        _context.Request.Headers[Headers.LegacyServiceId] = "admin";
        _legacyOnly = _policy.Evaluate(_context, _config);

        _context.Request.Headers[Headers.ServiceId] = "portal";
        _bothNamingDifferentServices = _policy.Evaluate(_context, _config);
    }

    [Fact] void should_apply_the_requirements_of_the_service_named_by_the_legacy_header() => _legacyOnly.IsGranted.ShouldBeFalse();
    [Fact] void should_apply_the_requirements_of_the_service_named_by_the_current_header_when_both_are_sent() => _bothNamingDifferentServices.IsGranted.ShouldBeTrue();
}
