// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SpoofableHeaders;

/// <summary>
/// Stripping is by prefix and by name, not by substring: a header that merely mentions an identity name, or
/// that the caller is entitled to send, is left alone so stripping cannot be turned into a way to break routing.
/// </summary>
public class when_stripping_beside_headers_that_only_resemble_identity
{
    [Theory]
    [InlineData("x-forwarded-for")]
    [InlineData("x-ms-request-id")]
    [InlineData("y-x-ms-client-principal")]
    [InlineData("x-cratis-microservice")]
    [InlineData("x-request-x-cratis-tenant-id")]
    [InlineData("x-cratis-on")]
    [InlineData("Accept-Language")]
    public void should_keep_the_header(string name)
    {
        var headers = new HeaderDictionary { [name] = "kept" };
        using var request = new HttpRequestMessage();
        request.Headers.TryAddWithoutValidation(name, "kept");

        SpoofableHeaders.Strip(headers);
        SpoofableHeaders.Strip(request.Headers);

        headers[name].ToString().ShouldEqual("kept");
        request.Headers.GetValues(name).Single().ShouldEqual("kept");
    }
}
