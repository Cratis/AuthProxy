// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

public class when_an_unknown_header_names_a_query_selected_service : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _current;
    AccessDecision _legacy;

    void Establish()
    {
        _config = new C.AuthProxy
        {
            Authorization = new C.Authorization { RequiredClaims = [Claiming("organization", "Cratis")] },
            Services = new Dictionary<string, C.Service>
            {
                ["portal"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://portal.test/" } },
                ["admin"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://admin.test/" },
                    Authorization = new C.Authorization { RequiredClaims = [Claiming("role", "admin")] }
                }
            }
        };
        CallerCarrying(new Claim("organization", "Cratis"));
        _context.Request.QueryString = new QueryString("?service=admin");
    }

    void Because()
    {
        _context.Request.Headers[Headers.ServiceId] = "unknown";
        _current = _policy.Evaluate(_context, _config);
        _context.Request.Headers.Remove(Headers.ServiceId);
        _context.Request.Headers[Headers.LegacyServiceId] = "unknown";
        _legacy = _policy.Evaluate(_context, _config);
    }

    [Fact] void should_enforce_query_service_requirements_with_an_unknown_current_header() => _current.IsGranted.ShouldBeFalse();
    [Fact] void should_enforce_query_service_requirements_with_an_unknown_legacy_header() => _legacy.IsGranted.ShouldBeFalse();
}
