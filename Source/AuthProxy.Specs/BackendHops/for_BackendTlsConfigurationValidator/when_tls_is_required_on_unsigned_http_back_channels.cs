// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_tls_is_required_on_unsigned_http_back_channels : when_identity_back_channels_use_plain_http
{
    protected override bool SigningConfigured => false;
    protected override bool RequireTls => true;
}
