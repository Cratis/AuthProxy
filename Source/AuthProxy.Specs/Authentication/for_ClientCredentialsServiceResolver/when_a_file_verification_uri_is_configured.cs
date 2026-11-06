// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsServiceResolver;

public class when_a_file_verification_uri_is_configured : Specification
{
    Uri? _address;

    void Because() => _address = ClientCredentialsServiceResolver.CreateVerificationUri("https://backend.example/", "file:///.cratis/client-credentials/verify");

    [Fact] void should_not_resolve_a_non_http_endpoint() => _address.ShouldBeNull();
}
