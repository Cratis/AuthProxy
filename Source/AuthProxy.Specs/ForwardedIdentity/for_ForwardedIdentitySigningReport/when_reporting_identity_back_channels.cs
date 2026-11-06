// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningReport;

public class when_reporting_identity_back_channels : Specification
{
    IReadOnlyList<ForwardedIdentityFlowStatus> _rows;

    void Because() => _rows = ForwardedIdentitySigningReport.For(new()
    {
        Services = new Dictionary<string, C.Service>
        {
            ["signed"] = new() { Backend = new() { BaseUrl = "https://signed.example" }, SignInCallback = new(), ForwardedIdentity = new() { KeyId = "spec-key", Audience = "spec-audience" } },
            ["legacy"] = new() { Backend = new() { BaseUrl = "http://legacy.example" }, SignInCallback = new() }
        },
        OnBehalf = new() { Service = "signed" },
        Invite = new() { StageUrl = "https://stage.example/stage", ExchangeUrl = "https://invite.example/exchange" },
        Link = new() { ExchangeUrl = "https://link.example/exchange" },
        SignIn = new() { NotifyUrl = "http://notify.example/notify" }
    });

    [Fact] void should_report_a_signed_callback() => _rows.Single(row => row.Flow == ForwardedIdentityFlow.SignInCallback && row.ServiceName == "signed").IsSigned.ShouldBeTrue();
    [Fact] void should_preserve_an_unsigned_callback() => _rows.Single(row => row.Flow == ForwardedIdentityFlow.SignInCallback && row.ServiceName == "legacy").IsSigned.ShouldBeFalse();
    [Fact] void should_report_on_behalf_as_attested() => Row(ForwardedIdentityFlow.OnBehalf).IsAttested.ShouldBeTrue();
    [Fact] void should_not_call_on_behalf_envelope_signed() => Row(ForwardedIdentityFlow.OnBehalf).IsSigned.ShouldBeFalse();
    [Fact] void should_report_invitation_staging_transport() => Row(ForwardedIdentityFlow.InvitationStage).Transport.ShouldEqual(BackendHops.BackendHopTransport.Tls);
    [Fact] void should_not_call_invitation_staging_signed() => Row(ForwardedIdentityFlow.InvitationStage).IsSigned.ShouldBeFalse();
    [Fact] void should_not_call_invitation_exchange_signed() => Row(ForwardedIdentityFlow.InvitationExchange).IsSigned.ShouldBeFalse();
    [Fact] void should_not_call_link_exchange_signed() => Row(ForwardedIdentityFlow.LinkExchange).IsSigned.ShouldBeFalse();
    [Fact] void should_report_sign_in_notification_transport() => Row(ForwardedIdentityFlow.SignInNotification).Transport.ShouldEqual(BackendHops.BackendHopTransport.PlainHttp);
    [Fact] void should_not_call_sign_in_notification_signed() => Row(ForwardedIdentityFlow.SignInNotification).IsSigned.ShouldBeFalse();

    ForwardedIdentityFlowStatus Row(ForwardedIdentityFlow flow) => _rows.Single(row => row.Flow == flow);
}
