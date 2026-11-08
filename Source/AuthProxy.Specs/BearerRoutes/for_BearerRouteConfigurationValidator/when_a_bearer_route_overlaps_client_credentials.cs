// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteConfigurationValidator;

/// <summary>
/// A bearer route may share exactly its own service's client-credentials route prefix. A nested prefix, in either
/// direction, or a prefix of another service fails at startup rather than leaving the path's owner unclear.
/// </summary>
public class when_a_bearer_route_overlaps_client_credentials : Specification
{
    [Theory]
    [InlineData("api", "/api", true)]
    [InlineData("api", "/API/", true)]
    [InlineData("api", "/elsewhere", true)]
    [InlineData("api", "/api/machine", false)]
    [InlineData("api", "/", false)]
    [InlineData("billing", "/api", false)]
    [InlineData("billing", "/api/machine", false)]
    [InlineData("billing", "/elsewhere", true)]
    public void should_accept_only_the_same_prefix_of_the_same_service(string clientCredentialsService, string clientCredentialsPrefix, bool valid)
    {
        var options = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["api"] = new()
                {
                    Backend = new() { BaseUrl = "https://backend.example.test" },
                    IdentityVerification = C.IdentityVerificationMode.BestEffort,
                    BearerRoutes = [new()
                    {
                        PathPrefix = "/api",
                        Issuers = [new() { Issuer = "https://issuer.example.test" }],
                        Audiences = ["direct-api"],
                        ResourceMetadataUrl = "https://direct.example.test/.well-known/oauth-protected-resource/api",
                    }],
                },
                ["billing"] = new()
                {
                    Backend = new() { BaseUrl = "https://billing.example.test" },
                    PathPrefix = "/billing",
                    IdentityVerification = C.IdentityVerificationMode.BestEffort,
                },
            },
        };
        options.Services[clientCredentialsService].ClientCredentials = new() { RoutePrefix = clientCredentialsPrefix, VerificationPath = "/verify" };

        var result = new BearerRouteConfigurationValidator().Validate(null, options);

        if (valid)
        {
            result.FailureMessage.ShouldBeNull();
        }
        else
        {
            result.FailureMessage.ShouldContain("client-credentials");
        }
    }
}
