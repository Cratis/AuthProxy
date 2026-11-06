// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_BootstrapReturnUrl;

public class when_validating_a_pending_flow : Specification
{
    [Theory]
    [InlineData("/register", true)]
    [InlineData("/register?campaign=signup", true)]
    [InlineData("https://other.test/register", false)]
    [InlineData("//other.test/register", false)]
    [InlineData("/\\other.test/register", false)]
    [InlineData("/tenant-b", false)]
    [InlineData("/register/../tenant-b", false)]
    [InlineData("/register%2f..%2ftenant-b", false)]
    [InlineData("/invite/other", false)]
    [InlineData(null, false)]
    public void should_allow_only_the_local_registration_path(string? returnUrl, bool allowed)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{Cookies.Registration}=true";
        BootstrapReturnUrl.IsAllowed(context, returnUrl).ShouldEqual(allowed);
    }

    [Theory]
    [InlineData("/invite/pending-token", true)]
    [InlineData("/invite/pending-token?source=mail", true)]
    [InlineData("/invite/other-token", false)]
    [InlineData("https://other.test/invite/pending-token", false)]
    [InlineData("//other.test/invite/pending-token", false)]
    [InlineData("/register", false)]
    [InlineData("/", false)]
    public void should_allow_only_the_local_pending_invitation_path(string returnUrl, bool allowed)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{Cookies.InviteToken}=pending-token";
        BootstrapReturnUrl.IsAllowed(context, returnUrl).ShouldEqual(allowed);
    }

    [Fact]
    public void should_leave_ordinary_login_redirect_validation_unchanged() =>
        BootstrapReturnUrl.IsAllowed(new DefaultHttpContext(), "/dashboard").ShouldBeTrue();
}
