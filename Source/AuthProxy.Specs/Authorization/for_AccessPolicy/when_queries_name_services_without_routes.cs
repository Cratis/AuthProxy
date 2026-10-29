// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

public class when_queries_name_services_without_routes : given.an_access_policy
{
    C.AuthProxy _config;

    void Establish()
    {
        _config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["portal"] = new(),
                ["admin"] = new() { Authorization = new C.Authorization { RequiredClaims = [Claiming("role", "admin")] } }
            }
        };
        CallerCarrying();
    }

    [Theory]
    [InlineData("?x-cratis-microservice=ADMIN", false)]
    [InlineData("?service=admin", false)]
    [InlineData("?x-cratis-microservice=admin&service=portal", false)]
    [InlineData("?x-cratis-microservice=portal&service=admin", true)]
    [InlineData("?x-cratis-microservice=admin&service=admin", false)]
    [InlineData("?x-cratis-microservice=unknown&service=admin", false)]
    [InlineData("?x-cratis-microservice=&service=admin", false)]
    [InlineData("?x-cratis-microservice=%20admin%20&service=portal", false)]
    [InlineData("?x-cratis-microservice=admin&service=unknown", false)]
    [InlineData("?x-cratis-microservice=unknown&service=missing", true)]
    public void should_apply_the_first_matching_named_services_requirements(string query, bool granted)
    {
        _context.Request.QueryString = new QueryString(query);
        _policy.Evaluate(_context, _config).IsGranted.ShouldEqual(granted);
    }

    [Theory]
    [InlineData("portal", true)]
    [InlineData("unknown", false)]
    public void should_keep_the_header_fallback_first(string header, bool granted)
    {
        _context.Request.Headers[Headers.ServiceId] = header;
        _context.Request.QueryString = new QueryString("?x-cratis-microservice=admin&service=portal");
        _policy.Evaluate(_context, _config).IsGranted.ShouldEqual(granted);
    }
}
