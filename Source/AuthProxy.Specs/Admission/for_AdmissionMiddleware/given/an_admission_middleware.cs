// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.Admission.given;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Admission.for_AdmissionMiddleware.given;

/// <summary>
/// The middleware wired to the real policy and a substituted capability handler, in front of a next that
/// records whether it ran.
/// <para>
/// The policy is the real one for the same reason the access-control specs use theirs: what these specs
/// are about is which requests reach the pipeline at all, and a substitute would answer the same way for a
/// request that should never have got past the gate — making a skipped check indistinguishable from a
/// passed one.
/// </para>
/// </summary>
public class an_admission_middleware : Specification
{
    protected FixedTime _time;
    protected IEntryTransactionProtector _protector;
    protected ICapabilityAdmission _admission;
    protected AdmissionMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected MemoryStream _responseBody;
    protected C.AuthProxy _config;
    protected bool _nextCalled;

    void Establish()
    {
        _time = new FixedTime(DateTimeOffset.UtcNow);
        _protector = new EntryTransactionProtector(new EphemeralDataProtectionProvider());
        _admission = Substitute.For<ICapabilityAdmission>();

        _config = new C.AuthProxy
        {
            Admission = new C.Admission
            {
                Mode = C.AdmissionMode.CapabilityOnly,
                Capability = new C.AdmissionCapability { VerifierUrl = "https://verifier.test/admit" },
            },
        };

        _responseBody = new MemoryStream();
        _context = new DefaultHttpContext();
        _context.Request.Path = "/";
        _context.Response.Body = _responseBody;
    }

    void Destroy() => _responseBody.Dispose();

    /// <summary>
    /// Builds the middleware over the current configuration.
    /// </summary>
    /// <remarks>
    /// Deferred to the spec rather than done in <c>Establish</c>, so a spec can change the configuration
    /// first — the options monitor captures the instance it is told about.
    /// </remarks>
    protected void BuildMiddleware()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(_config);

        _middleware = new AdmissionMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            config,
            new AdmissionPolicy(_protector, _time),
            _admission);
    }

    /// <summary>
    /// Puts a live entry transaction on the request.
    /// </summary>
    protected void PresentingALiveEntryTransaction()
    {
        var transaction = new EntryTransaction(
            "3f9c0a1b7e2d4c6f",
            "8b1d5e7a0c3f2941",
            _time.GetUtcNow().AddMinutes(10));

        _context.Request.Headers.Cookie = $"{Cookies.EntryTransaction}={_protector.Protect(transaction)}";
    }

    /// <summary>
    /// Reads back what was written to the response.
    /// </summary>
    /// <returns>The response body.</returns>
    protected string WrittenBody() => Encoding.UTF8.GetString(_responseBody.ToArray());
}
