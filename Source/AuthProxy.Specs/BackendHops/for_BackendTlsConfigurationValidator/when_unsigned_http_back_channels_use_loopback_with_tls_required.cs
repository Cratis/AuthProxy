// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_unsigned_http_back_channels_use_loopback_with_tls_required : when_identity_back_channels_use_loopback_http_in_local_development
{
    protected override bool SigningConfigured => false;
    protected override bool RequireTls => true;
}
