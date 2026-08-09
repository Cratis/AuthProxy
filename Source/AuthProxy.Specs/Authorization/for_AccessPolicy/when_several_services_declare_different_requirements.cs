// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// The service a request targets is worked out the way the route table works it out, so a service's
/// requirements apply to that service's traffic and to nothing else.
/// <para>
/// The gate runs before endpoint selection — it has to refuse a caller before a tenant is resolved or a
/// backend is called, and long before YARP picks a route — so it cannot ask which route was chosen and has
/// to read the request the same way the route table will. That is the <c>Service-ID</c> header, then the
/// <c>service</c> query parameter. If the two ever disagreed, one service's requirements would guard
/// another service's traffic.
/// </para>
/// </summary>
public class when_several_services_declare_different_requirements : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _selectedByHeader;
    AccessDecision _selectedByQueryParameter;
    AccessDecision _selectingNoService;

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

        _context.Request.Headers[Headers.ServiceId] = "admin";
        _selectedByHeader = _policy.Evaluate(_context, _config);

        _context.Request.Headers.Remove(Headers.ServiceId);
        _context.Request.QueryString = new QueryString("?service=admin");
        _selectedByQueryParameter = _policy.Evaluate(_context, _config);

        _context.Request.QueryString = QueryString.Empty;
        _selectingNoService = _policy.Evaluate(_context, _config);
    }

    [Fact] void should_apply_the_requirements_of_the_service_named_by_the_header() => _selectedByHeader.IsGranted.ShouldBeFalse();
    [Fact] void should_apply_the_requirements_of_the_service_named_by_the_query_parameter() => _selectedByQueryParameter.IsGranted.ShouldBeFalse();
    [Fact] void should_not_apply_one_service_requirements_to_a_request_naming_no_service() => _selectingNoService.IsGranted.ShouldBeTrue();
}
