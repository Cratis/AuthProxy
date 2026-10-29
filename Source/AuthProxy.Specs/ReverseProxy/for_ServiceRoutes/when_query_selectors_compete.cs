// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes;

public class when_query_selectors_compete : given.services_routed_by_host_and_path
{
    [Theory]
    [InlineData("/api/customers", "?x-cratis-microservice=PORTAL", "portal")]
    [InlineData("/api/customers", "?service=PORTAL", "portal")]
    [InlineData("/customers", "?x-cratis-microservice=billing", "billing")]
    [InlineData("/customers", "?service=billing", "billing")]
    [InlineData("/api/customers", "?x-cratis-microservice=portal&service=billing", "portal")]
    [InlineData("/api/customers", "?x-cratis-microservice=portal&service=portal", "portal")]
    [InlineData("/api/customers", "?x-cratis-microservice=unknown&service=portal", "portal")]
    [InlineData("/api/customers", "?x-cratis-microservice=portal&service=unknown", "portal")]
    [InlineData("/api/customers", "?x-cratis-microservice=&service=portal", "portal")]
    [InlineData("/api/customers", "?x-cratis-microservice=%20portal%20&service=billing", "billing")]
    [InlineData("/api/customers", "?x-cratis-microservice=unknown&service=missing", null)]
    [InlineData("/customers", "?x-cratis-microservice=billing&service=reports", "billing")]
    [InlineData("/customers", "?x-cratis-microservice=unknown&service=reports", "reports")]
    [InlineData("/customers", "?x-cratis-microservice=&service=reports", "reports")]
    [InlineData("/reports/api/customers", "?x-cratis-microservice=billing&service=portal", "reports")]
    public void should_prefer_a_matching_canonical_query_within_the_endpoint_category(string path, string query, string? expected)
    {
        Request("www.example.com", path);
        _context.Request.QueryString = new QueryString(query);
        Resolve();
        (_result?.Name).ShouldEqual(expected);
    }

    [Theory]
    [InlineData("/api/customers", "billing")]
    [InlineData("/customers", "billing")]
    public void should_keep_headers_ahead_of_queries(string path, string expected)
    {
        Request("www.example.com", path);
        _context.Request.Headers[Headers.ServiceId] = "billing";
        _context.Request.QueryString = new QueryString("?x-cratis-microservice=reports&service=portal");
        Resolve();
        _result.Name.ShouldEqual(expected);
    }

    [Theory]
    [InlineData("?x-cratis-microservice=portal&service=billing", "portal")]
    [InlineData("?x-cratis-microservice=unknown&service=missing", "billing")]
    public void should_use_hosts_only_after_matching_queries(string query, string expected)
    {
        Request("billing.example.com", "/api/customers");
        _context.Request.QueryString = new QueryString(query);
        Resolve();
        _result.Name.ShouldEqual(expected);
    }

    [Theory]
    [InlineData("?x-cratis-microservice=billing&service=portal", "portal")]
    [InlineData("?x-cratis-microservice=portal&service=billing", "portal")]
    public void should_keep_backend_candidates_ahead_of_frontend_candidates(string query, string expected)
    {
        _config.Services["billing"].Backend = null;
        Request("www.example.com", "/api/customers");
        _context.Request.QueryString = new QueryString(query);
        Resolve();
        _result.Name.ShouldEqual(expected);
    }

    [Fact]
    public void should_preserve_single_service_resolution()
    {
        _config.Services = new Dictionary<string, C.Service> { ["portal"] = _config.Services["portal"] };
        Request("www.example.com", "/api/customers");
        _context.Request.QueryString = new QueryString("?x-cratis-microservice=unknown&service=missing");
        Resolve();
        _result.Name.ShouldEqual("portal");
    }
}
