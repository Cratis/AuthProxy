// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

public class when_forwarding_the_effective_scheme
{
    [Theory]
    [InlineData("https", false, "http")]
    [InlineData("http", true, "https")]
    public async Task should_forward_one_effective_scheme_not_the_caller_value(string scheme, bool trusted, string supplied)
    {
        await using var harness = new SchemeHarness(trusted);
        using var client = harness.CreateBearerClient();
        client.BaseAddress = new Uri($"{scheme}://public.example.test");
        const string path = "/mcp/effective-scheme";
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token());
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", supplied);

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("https", harness.Origin.LastRequestTo(path)!.Value("X-Forwarded-Proto"));
    }

    sealed class SchemeHarness(bool trusted) : BearerRouteHarness
    {
        protected override void AddSettings(IDictionary<string, string?> settings)
        {
            if (trusted)
            {
                settings[$"{C.Ingress.SectionKey}:TrustedProxies:0"] = "203.0.113.9";
            }
        }

        protected override void ConfigureHost(IWebHostBuilder builder) =>
            builder.ConfigureTestServices(services => services.AddSingleton<IStartupFilter>(new PeerStartupFilter()));
    }

    sealed class PeerStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, continuation) =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.9");
                return continuation(context);
            });
            next(app);
        };
    }
}
