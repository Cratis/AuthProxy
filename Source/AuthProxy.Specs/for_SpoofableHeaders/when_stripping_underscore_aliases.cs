// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SpoofableHeaders;

public class when_stripping_underscore_aliases
{
    [Theory]
    [InlineData("x_ms_client_principal_id")]
    [InlineData("X_MS_CLIENT_PRINCIPAL")]
    [InlineData("x_ms_client_principal_custom")]
    [InlineData("x_cratis_tenant_id")]
    [InlineData("Tenant_ID")]
    [InlineData("x_cratis_on_behalf_actor")]
    [InlineData("x_cratis_on_behalf_custom")]
    [InlineData("x_cratis_sign_in_callback_secret")]
    [InlineData("x_cratis_forwarded_identity_signature")]
    [InlineData("X_CRATIS_FORWARDED_IDENTITY_VERSION")]
    [InlineData("x_cratis_credential_kind")]
    [InlineData("x_cratis_issuer")]
    [InlineData("x_cratis_token_client_id")]
    [InlineData("x_cratis_token_scope")]
    public void should_strip_identity_aliases_on_ingress_and_egress(string name)
    {
        var headers = new HeaderDictionary { [name] = "caller-context", ["x_custom_header"] = "custom" };
        using var request = new HttpRequestMessage();
        request.Headers.Add(name, "caller-context");
        request.Headers.Add("x_custom_header", "custom");

        SpoofableHeaders.Strip(headers);
        SpoofableHeaders.Strip(request.Headers);

        headers.ContainsKey(name).ShouldBeFalse();
        request.Headers.Contains(name).ShouldBeFalse();
        headers["x_custom_header"].ToString().ShouldEqual("custom");
        request.Headers.GetValues("x_custom_header").Single().ShouldEqual("custom");
    }
}
