// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Security.for_SessionContextForwarding;

public class when_an_inbound_sign_in_provider_is_spoofed : given.a_session_context
{
    [Fact] public Task should_discard_the_provider_claim_header_and_forged_envelope() => RejectSpoof(SessionClaims.SignInProvider, "sign-in-provider");
}
