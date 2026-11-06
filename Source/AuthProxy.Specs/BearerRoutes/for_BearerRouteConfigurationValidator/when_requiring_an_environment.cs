// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteConfigurationValidator;

public class when_requiring_an_environment : Specification
{
    [Theory]
    [InlineData("", "env", false)]
    [InlineData("staging", "env", true)]
    [InlineData("staging", " env", false)]
    [InlineData("staging", " ", false)]
    public void should_require_a_deployment_environment_and_an_unpadded_claim_type(string environment, string claimType, bool valid)
    {
        var options = new C.AuthProxy
        {
            CredentialBinding = new() { Environment = environment },
            Services = new Dictionary<string, C.Service>
            {
                ["api"] = new()
                {
                    Backend = new() { BaseUrl = "https://backend.example.test" },
                    IdentityVerification = C.IdentityVerificationMode.BestEffort,
                    BearerRoutes = [new()
                    {
                        PathPrefix = "/mcp",
                        Issuers = [new() { Issuer = "https://issuer.example.test" }],
                        Audiences = ["direct-api"],
                        ResourceMetadataUrl = "https://direct.example.test/.well-known/oauth-protected-resource/mcp",
                        EnvironmentClaimType = claimType,
                    }],
                },
            },
        };
        new BearerRouteConfigurationValidator().Validate(null, options).Succeeded.ShouldEqual(valid);
    }
}
