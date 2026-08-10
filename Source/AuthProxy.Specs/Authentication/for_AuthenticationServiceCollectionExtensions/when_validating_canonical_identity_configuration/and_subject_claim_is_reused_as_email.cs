// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.when_validating_canonical_identity_configuration;

public class and_subject_claim_is_reused_as_email : canonical_configuration_validation
{
    Exception? _exception;

    void Because()
    {
        var configuration = ValidOidcProvider(subjectClaimType: "email");
        _exception = ResolveAuthenticationOptions(BuildServices(configuration));
    }

    [Fact] void should_fail_configuration_validation() => _exception.ShouldBeOfExactType<OptionsValidationException>();
}
