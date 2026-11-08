// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SpoofableHeaders;

/// <summary>
/// A caller who sends the same header several times, in several cases, or with hyphens and underscores mixed
/// in one name gets no copy through: every value goes, not only the first.
/// </summary>
public class when_stripping_repeated_and_mixed_separator_headers
{
    [Theory]
    [InlineData("x-ms-client-principal-id")]
    [InlineData("X-MS-CLIENT-PRINCIPAL")]
    [InlineData("x-ms_client-principal")]
    [InlineData("x_ms-client_principal-name")]
    [InlineData("x-cratis-tenant-id")]
    [InlineData("Tenant-ID")]
    [InlineData("X_Cratis-Tenant_Id")]
    [InlineData("x-cratis-on-behalf-assertion")]
    [InlineData("X-Cratis_On_Behalf-Actor")]
    [InlineData("x-cratis-forwarded-identity-signature")]
    [InlineData("x-cratis-credential_kind")]
    public void should_strip_every_value_on_ingress_and_egress(string name)
    {
        var headers = new HeaderDictionary { [name] = new[] { "first", "second", "third" } };
        using var request = new HttpRequestMessage();
        request.Headers.TryAddWithoutValidation(name, ["first", "second", "third"]);

        SpoofableHeaders.Strip(headers);
        SpoofableHeaders.Strip(request.Headers);

        headers.ContainsKey(name).ShouldBeFalse();
        request.Headers.Contains(name).ShouldBeFalse();
    }

    [Theory]
    [InlineData("x-ms-client-principal-id", "X-Ms-Client-Principal-Id")]
    [InlineData("x-cratis-tenant-id", "X-CRATIS-TENANT-ID")]
    [InlineData("x-cratis-on-behalf-actor", "x_cratis_on_behalf_actor")]
    public void should_strip_the_other_spelling_of_a_name_sent_twice(string first, string second)
    {
        using var request = new HttpRequestMessage();
        request.Headers.TryAddWithoutValidation(first, "caller-one");
        request.Headers.TryAddWithoutValidation(second, "caller-two");

        SpoofableHeaders.Strip(request.Headers);

        request.Headers.Contains(first).ShouldBeFalse();
        request.Headers.Contains(second).ShouldBeFalse();
    }
}
