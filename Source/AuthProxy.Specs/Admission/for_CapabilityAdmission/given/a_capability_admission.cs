// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.Admission.given;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Admission.for_CapabilityAdmission.given;

/// <summary>
/// The admission handler over a substituted verifier and a real protector, so a spec decides what the
/// verifier says and can still read back exactly what went into the browser.
/// </summary>
public class a_capability_admission : Specification
{
    protected const string Capability = "cap-7c1e9a4b2f6d0835-presented-value";

    protected FixedTime _time;
    protected IEntryTransactionProtector _protector;
    protected ICapabilityVerifier _verifier;
    protected CapabilityAdmission _admission;
    protected C.AuthProxy _config;
    protected DefaultHttpContext _context;
    protected bool _admitted;

    void Establish()
    {
        _time = new FixedTime(DateTimeOffset.UtcNow);
        _protector = new EntryTransactionProtector(new EphemeralDataProtectionProvider());
        _verifier = Substitute.For<ICapabilityVerifier>();
        _verifier
            .Verify(Arg.Any<CapabilityPresentation>(), Arg.Any<CancellationToken>())
            .Returns(CapabilityVerification.Denied);

        _admission = new CapabilityAdmission(_verifier, _protector, _time);

        _config = new C.AuthProxy
        {
            Admission = new C.Admission
            {
                Mode = C.AdmissionMode.CapabilityOnly,
                EntryLifetime = TimeSpan.FromMinutes(10),
                Capability = new C.AdmissionCapability { VerifierUrl = "https://verifier.test/admit" },
            },
        };

        _context = new DefaultHttpContext();
        _context.Request.Path = "/.cratis/admission";
        _context.Request.Method = HttpMethods.Post;
    }

    /// <summary>
    /// Puts the given capability on the request as its body.
    /// </summary>
    /// <param name="capability">The value to present.</param>
    protected void Presenting(string capability)
    {
        var bytes = Encoding.UTF8.GetBytes(capability);
        _context.Request.Body = new MemoryStream(bytes);
        _context.Request.ContentLength = bytes.Length;
    }

    /// <summary>
    /// Has the verifier admit whatever it is asked about.
    /// </summary>
    protected void VerifierAdmitting() =>
        _verifier
            .Verify(Arg.Any<CapabilityPresentation>(), Arg.Any<CancellationToken>())
            .Returns(CapabilityVerification.Admitted);

    /// <summary>
    /// Gets the raw value of the entry-transaction cookie the response carries.
    /// </summary>
    /// <returns>The raw cookie value, or an empty string when none was issued.</returns>
    protected string IssuedCookieValue()
    {
        var setCookie = _context.Response.Headers.SetCookie.FirstOrDefault(_ => _?.StartsWith(Cookies.EntryTransaction, StringComparison.Ordinal) == true);
        if (setCookie is null)
        {
            return string.Empty;
        }

        var value = setCookie[(setCookie.IndexOf('=', StringComparison.Ordinal) + 1)..];
        var end = value.IndexOf(';', StringComparison.Ordinal);

        return end < 0 ? value : value[..end];
    }

    /// <summary>
    /// Gets the whole <c>Set-Cookie</c> header the response carries for the entry transaction.
    /// </summary>
    /// <returns>The header value, or an empty string when none was issued.</returns>
    protected string IssuedCookieHeader() =>
        _context.Response.Headers.SetCookie.FirstOrDefault(_ => _?.StartsWith(Cookies.EntryTransaction, StringComparison.Ordinal) == true) ?? string.Empty;
}
