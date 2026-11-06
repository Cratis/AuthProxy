// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_an_unsigned_deployment_uses_plain_http_back_channels : identity_back_channels
{
    protected override bool SigningConfigured => false;

    void Because() => _result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, _configuration);

    [Fact] void should_preserve_unsigned_transport() => _result.Succeeded.ShouldBeTrue();
}
