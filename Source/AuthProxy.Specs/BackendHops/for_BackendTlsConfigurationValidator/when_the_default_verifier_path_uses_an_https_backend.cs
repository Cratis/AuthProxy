// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_the_default_verifier_path_uses_an_https_backend : client_verifier_validation
{
    void Because() => Validate();

    [Fact] void should_accept_the_default_leading_slash_path() => _result.Succeeded.ShouldBeTrue();
}
