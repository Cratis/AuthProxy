// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SpoofableHeaders;

public class when_stripping_forwarded_identity_v2_context_headers
{
    [Theory]
    [InlineData("x-cratis-forwarded-identity-version")]
    [InlineData("x-cratis-credential-kind")]
    [InlineData("x-cratis-credential-id")]
    [InlineData("x-cratis-issuer")]
    [InlineData("x-cratis-subject")]
    [InlineData("x-cratis-idp")]
    [InlineData("x-cratis-auth-time")]
    [InlineData("x-cratis-acr")]
    [InlineData("x-cratis-amr")]
    [InlineData("x-cratis-act")]
    [InlineData("x-cratis-grant-id")]
    [InlineData("x-cratis-policy-epoch")]
    [InlineData("x-cratis-sender-binding")]
    [InlineData("x-cratis-forwarded-token-sha256")]
    [InlineData("x-cratis-assurance")]
    [InlineData("x-cratis-actor")]
    [InlineData("x-cratis-dpop-result")]
    public void should_strip_every_context_name_on_ingress_and_egress(string name)
    {
        var headers = new HeaderDictionary { [name.ToUpperInvariant()] = "caller-context", ["Accept"] = "application/json", ["x-cratis-microservice"] = "app", ["Service-ID"] = "app" };
        using var request = new HttpRequestMessage();
        request.Headers.Add(name, "caller-context");
        request.Headers.Add("Accept", "application/json");
        request.Headers.Add("x-cratis-microservice", "app");
        request.Headers.Add("Service-ID", "app");

        SpoofableHeaders.Strip(headers);
        SpoofableHeaders.Strip(request.Headers);

        headers.ContainsKey(name).ShouldBeFalse();
        request.Headers.Contains(name).ShouldBeFalse();
        headers["Accept"].ToString().ShouldEqual("application/json");
        request.Headers.GetValues("Accept").Single().ShouldEqual("application/json");
        headers["x-cratis-microservice"].ToString().ShouldEqual("app");
        request.Headers.GetValues("x-cratis-microservice").Single().ShouldEqual("app");
        headers["Service-ID"].ToString().ShouldEqual("app");
        request.Headers.GetValues("Service-ID").Single().ShouldEqual("app");
    }
}
