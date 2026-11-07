// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_BootstrapReturnUrl;

public class when_validating_a_pending_flow : Specification
{
    [Theory]
    [InlineData("/register", true, true)]
    [InlineData("/register?campaign=signup", true, true)]
    [InlineData("https://other.test/register", false, true)]
    [InlineData("//other.test/register", false, true)]
    [InlineData("/\\other.test/register", false, true)]
    [InlineData("/tenant-b", true, false)]
    [InlineData("/register/../tenant-b", true, false)]
    [InlineData("/register%2f..%2ftenant-b", true, false)]
    [InlineData("/invite/other", true, false)]
    [InlineData("/", true, false)]
    [InlineData("", true, false)]
    [InlineData(null, true, false)]
    public void should_preserve_registration_only_for_its_destination(string? returnUrl, bool allowed, bool pending)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{Cookies.Registration}=true; ordinary=some%2Fvalue";
        BootstrapReturnUrl.PrepareLogin(context, returnUrl).ShouldEqual(allowed);
        context.HasPendingRegistration().ShouldEqual(pending);
        context.Request.Cookies["ordinary"].ShouldEqual("some/value");
        if (!pending)
        {
            context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Registration}=;");
        }
    }

    [Theory]
    [InlineData("/invite/pending-token", true, true)]
    [InlineData("/invite/pending-token?source=mail", true, true)]
    [InlineData("/invite/other-token", true, false)]
    [InlineData("https://other.test/invite/pending-token", false, true)]
    [InlineData("//other.test/invite/pending-token", false, true)]
    [InlineData("/register", true, false)]
    [InlineData("/", true, false)]
    [InlineData(null, true, false)]
    public void should_preserve_only_the_matching_pending_invitation(string? returnUrl, bool allowed, bool pending)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{Cookies.InviteToken}=pending-token; {Cookies.InvitationEntryState}=entry-state";
        BootstrapReturnUrl.PrepareLogin(context, returnUrl).ShouldEqual(allowed);
        context.HasPendingInvitation().ShouldEqual(pending);
        context.Request.Cookies.ContainsKey(Cookies.InvitationEntryState).ShouldEqual(pending);
        if (!pending)
        {
            context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.InviteToken}=;");
            context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.InvitationEntryState}=;");
        }
    }

    [Fact]
    public void should_leave_ordinary_login_redirect_validation_unchanged() =>
        BootstrapReturnUrl.PrepareLogin(new DefaultHttpContext(), "/dashboard").ShouldBeTrue();
}
