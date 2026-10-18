// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;
using Cratis.AuthProxy.ForwardedIdentity.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.when_signing_a_request;

/// <summary>
/// An anonymous request is still signed, so a tenant header never reaches a verifying backend unsigned: the
/// assertion simply leaves out the claims there is nothing to say about.
/// </summary>
public class and_the_request_is_anonymous : a_forwarded_identity_signer
{
    HttpRequestMessage _withTenant;
    HttpRequestMessage _withNothing;
    Assertion _tenantOnly;
    Assertion _bare;

    void Establish()
    {
        _withTenant = Request(headers: [(Headers.TenantId, Tenant)]);
        _withNothing = Request();
    }

    void Because()
    {
        _signer.Sign(_withTenant, "reports");
        _signer.Sign(_withNothing, "reports");
        _tenantOnly = Assertion.Parse(AssertionOf(_withTenant));
        _bare = Assertion.Parse(AssertionOf(_withNothing));
    }

    [Fact] void should_leave_out_the_subject_of_a_tenant_only_request() => _tenantOnly.Text("sub").ShouldBeNull();
    [Fact] void should_name_the_tenant_of_a_tenant_only_request() => _tenantOnly.Text("tid").ShouldEqual(Tenant);
    [Fact] void should_digest_only_the_tenant_header() => _tenantOnly.Text("fwh").ShouldEqual(ForwardedIdentityToken.Digest($"{Headers.TenantId}:{Tenant}\n"));
    [Fact] void should_keep_the_order_of_the_remaining_claims() => string.Join(',', _tenantOnly.ClaimNames).ShouldEqual("iss,aud,iat,nbf,exp,jti,htm,htp,tid,fwh");
    [Fact] void should_leave_out_both_subject_and_tenant_when_there_are_none() => string.Join(',', _bare.ClaimNames).ShouldEqual("iss,aud,iat,nbf,exp,jti,htm,htp,fwh");
    [Fact] void should_digest_the_empty_header_set() => _bare.Text("fwh").ShouldEqual(ForwardedIdentityToken.Digest(string.Empty));
    [Fact] void should_verify_the_bare_assertion() => _bare.VerifiesWith(_publicKeyPem).ShouldBeTrue();
}
