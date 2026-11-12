// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Ingress;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteWarnings;

public class when_no_ingress_proxy_is_trusted : Specification
{
    [Theory]
    [InlineData(C.DeploymentProfile.Default, false, true)]
    [InlineData(C.DeploymentProfile.Default, true, false)]
    [InlineData(C.DeploymentProfile.LocalDevelopment, false, false)]
    public void should_warn_only_outside_local_development_without_a_trusted_ingress(C.DeploymentProfile profile, bool trusted, bool expected)
    {
        var config = new C.AuthProxy
        {
            Profile = profile,
            Services = new Dictionary<string, C.Service>
            {
                ["api"] = new()
                {
                    Backend = new() { BaseUrl = "https://backend.example.test" },
                    BearerRoutes = [new() { PathPrefix = "/api", Issuers = [new() { Issuer = "https://issuer.example.test" }], Audiences = ["api"], ResourceMetadataUrl = "https://api.example.test/.well-known/oauth-protected-resource" }],
                },
            },
        };
        var policy = new TrustedProxyPolicy(Options.Create(new C.Ingress { TrustedProxies = trusted ? ["203.0.113.9"] : [] }));

        var warnings = BearerRouteWarnings.For(config, policy).Where(warning => warning.Kind == BearerRouteWarningKind.NoTrustedIngress).ToArray();

        warnings.Length.ShouldEqual(expected ? 1 : 0);
        if (expected)
        {
            warnings[0].Prefix.ShouldEqual("/api");
            warnings[0].ServiceName.ShouldEqual("api");
        }
    }
}
