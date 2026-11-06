// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_full_url_back_channels_use_https_paths : full_url_back_channels_validation
{
    void Because() => Validate();

    [Fact] void should_accept_the_configured_https_urls_and_templates() => _result.Succeeded.ShouldBeTrue();
}
