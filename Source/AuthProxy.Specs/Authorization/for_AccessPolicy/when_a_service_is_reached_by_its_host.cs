// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// A host or path prefix that routes a request to a service also subjects it to that service's requirements, so
/// declaring a host is not a way around them.
/// </summary>
public class when_a_service_is_reached_by_its_host : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _byHost;
    AccessDecision _byPrefix;
    AccessDecision _byHostNamingAnother;

    void Establish() => _config = new C.AuthProxy
    {
        Services = new Dictionary<string, C.Service>
        {
            ["admin"] = new()
            {
                Hosts = ["admin.example.com"],
                Backend = new C.ServiceEndpoint { BaseUrl = "http://admin.test/" },
                Authorization = new C.Authorization { RequiredClaims = [Claiming("urn:github:team", "Cratis/operations")] },
            },
            ["audit"] = new()
            {
                PathPrefix = "/audit",
                Frontend = new C.ServiceEndpoint { BaseUrl = "http://audit.test/" },
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

        _context.Request.Host = new HostString("admin.example.com");
        _context.Request.Path = "/api/users";
        _byHost = _policy.Evaluate(_context, _config);

        _context.Request.Host = new HostString("www.example.com");
        _context.Request.Path = "/audit/log";
        _context.Request.Headers[Headers.ServiceId] = "portal";
        _byPrefix = _policy.Evaluate(_context, _config);

        _context.Request.Host = new HostString("admin.example.com");
        _context.Request.Path = "/api/users";
        _byHostNamingAnother = _policy.Evaluate(_context, _config);
    }

    [Fact] void should_apply_the_requirements_of_the_service_declaring_the_host() => _byHost.IsGranted.ShouldBeFalse();
    [Fact] void should_apply_the_requirements_of_the_service_declaring_the_prefix_whatever_the_header_says() => _byPrefix.IsGranted.ShouldBeFalse();
    [Fact] void should_apply_the_requirements_of_the_explicitly_named_service_on_a_host() => _byHostNamingAnother.IsGranted.ShouldBeTrue();
}
