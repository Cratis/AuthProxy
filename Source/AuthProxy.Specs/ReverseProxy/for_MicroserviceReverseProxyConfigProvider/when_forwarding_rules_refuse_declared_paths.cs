// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

public class when_forwarding_rules_refuse_declared_paths : Specification
{
    [Theory]
    [InlineData("AnonymousPaths", "/reports/api/hook")]
    [InlineData("BearerRoutes", "/mcp")]
    [InlineData("ResourceMetadataPath", "/.well-known/oauth-protected-resource/mcp")]
    public void should_warn_without_adding_implicit_allow_rules(string kind, string path)
    {
        var service = Service();
        service.ForwardedPaths = [new() { Path = "/api/other" }];
        var logger = Build(service);
        var warnings = Warnings(logger);
        warnings.Length.ShouldEqual(3);
        warnings.ShouldContain($"Service 'reports' declares {kind} '{path}', but its forwarding policy refuses it; requests there are answered 404.");
        service.ForwardedPaths.Single().Path.ShouldEqual("/api/other");
    }

    [Fact]
    void should_account_for_prefix_stripping()
    {
        var service = Service();
        service.ForwardedPaths = [new() { Path = "/api/hook" }, new() { Path = "/mcp" }, new() { Path = "/.well-known/oauth-protected-resource/mcp" }];
        Warnings(Build(service)).ShouldBeEmpty();
    }

    [Fact]
    void should_not_warn_when_no_forwarding_rules_are_configured() => Warnings(Build(Service())).ShouldBeEmpty();

    static C.Service Service() => new()
    {
        Backend = new() { BaseUrl = "https://backend.example.test/" },
        PathPrefix = "/reports",
        StripPathPrefix = true,
        AnonymousPaths = ["/reports/api/hook"],
        BearerRoutes = [new()
        {
            PathPrefix = "/mcp",
            ResourceMetadataUrl = "https://reports.example.test/.well-known/oauth-protected-resource/mcp",
            Issuers = [new() { Issuer = "https://issuer.example.test/" }],
            Audiences = ["reports"]
        }]
    };

    static RecordingLogger<MicroserviceReverseProxyConfigProvider> Build(C.Service service)
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["reports"] = service } });
        var logger = new RecordingLogger<MicroserviceReverseProxyConfigProvider>();
        using var provider = new MicroserviceReverseProxyConfigProvider(monitor, logger);
        return logger;
    }

    static string[] Warnings(RecordingLogger<MicroserviceReverseProxyConfigProvider> logger) => logger.Messages
        .Where((_, index) => logger.Levels[index] == LogLevel.Warning)
        .ToArray();
}
