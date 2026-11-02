using System.Net;
using AuthenticationAPI.Models.Enums;
using Microsoft.EntityFrameworkCore;
using Xunit;
using static AuthenticationAPI.Tests.Integration.ApiFixture;

namespace AuthenticationAPI.Tests.Integration;

[Trait("Category", "Integration")]
public class MfaTests(ApiFixture fx) : IClassFixture<ApiFixture>
{
    private async Task<(TestUser User, HttpClient Client)> MfaUserAsync()
    {
        var c = fx.NewClient();
        var u = await fx.RegisterVerifiedAsync(c);
        await fx.EnableMfaAsync(c, u);
        return (u, c);
    }

    private static Task<Resp> Verify(HttpClient c, TestUser u, string? challenge, string otp, string method = "Totp", bool trust = false) =>
        Post(c, "/api/auth/mfa/verify", new { email = u.Email, otp, method, challengeToken = challenge, trustThisDevice = trust });

    [SqlFact]
    public async Task Login_with_mfa_returns_a_challenge_and_no_tokens_until_the_second_factor_is_proven()
    {
        var (u, c) = await MfaUserAsync();
        var login = await fx.LoginAsync(c, u);
        Assert.Equal(HttpStatusCode.OK, login.Status);
        Assert.Null(login.Token);
        Assert.Null(login.RefreshToken);
        Assert.NotNull(login.Challenge);

        await fx.ClearTotpStep(u.Id);
        var done = await Verify(c, u, login.Challenge, await fx.TotpFor(u.Id));
        Assert.True(done.Success, done.Raw);
        Assert.NotNull(done.Token);
        Assert.NotNull(done.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, (await Get(c, "/api/auth/user", done.Token)).Status);
    }

    [SqlFact]
    public async Task Mfa_verify_without_a_valid_challenge_is_refused_even_with_a_correct_code_regression_for_password_bypass()
    {
        var (u, c) = await MfaUserAsync();
        await fx.ClearTotpStep(u.Id);
        var code = await fx.TotpFor(u.Id);

        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, null, code)).Status);                 // missing
        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, new string('q', 43), code)).Status);  // invented
        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, "short", code)).Status);              // malformed
    }

    [SqlFact]
    public async Task A_challenge_is_bound_to_one_account()
    {
        var (u, c) = await MfaUserAsync();
        var (other, _) = await MfaUserAsync();
        var login = await fx.LoginAsync(c, u);
        await fx.ClearTotpStep(other.Id);

        var r = await Verify(c, other, login.Challenge, await fx.TotpFor(other.Id)); // victim's code, attacker's challenge
        Assert.Equal(HttpStatusCode.BadRequest, r.Status);
        Assert.Null(r.Token);
    }

    [SqlFact]
    public async Task A_challenge_is_single_use_and_a_totp_code_cannot_be_replayed()
    {
        var (u, c) = await MfaUserAsync();
        var first = await fx.LoginAsync(c, u);
        await fx.ClearTotpStep(u.Id);
        var code = await fx.TotpFor(u.Id);
        Assert.True((await Verify(c, u, first.Challenge, code)).Success);

        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, first.Challenge, code)).Status); // same challenge again

        var second = await fx.LoginAsync(c, u);
        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, second.Challenge, code)).Status); // same code, fresh challenge: replay
        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, second.Challenge, await fx.TotpFor(u.Id, -1))).Status); // older step also refused
    }

    [SqlFact]
    public async Task Concurrent_verification_with_one_valid_code_issues_exactly_one_session()
    {
        var (u, c) = await MfaUserAsync();
        var login = await fx.LoginAsync(c, u);
        await fx.ClearTotpStep(u.Id);
        var code = await fx.TotpFor(u.Id);

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Verify(fx.NewClient(), u, login.Challenge, code)));
        Assert.Equal(1, results.Count(r => r.Success));
    }

    [SqlFact]
    public async Task Brute_forcing_codes_is_stopped_by_the_per_challenge_attempt_limit()
    {
        var (u, c) = await MfaUserAsync();
        var login = await fx.LoginAsync(c, u);
        await fx.ClearTotpStep(u.Id);

        var wrong = (await fx.TotpFor(u.Id)) == "000000" ? "111111" : "000000";
        for (var i = 0; i < 5; i++) Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, login.Challenge, wrong)).Status);

        var late = await Verify(c, u, login.Challenge, await fx.TotpFor(u.Id)); // even the right code is now refused
        Assert.Equal((HttpStatusCode)429, late.Status);
        Assert.Null(late.Token);
        Assert.True(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "mfa.challenge_exhausted" && e.UserId == u.Id)));
    }

    [SqlFact]
    public async Task Expired_challenges_are_rejected()
    {
        var (u, c) = await MfaUserAsync();
        var login = await fx.LoginAsync(c, u);
        await fx.Db(d => d.MfaChallenges.Where(x => x.UserId == u.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, DateTime.UtcNow.AddMinutes(-1))));
        await fx.ClearTotpStep(u.Id);
        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, login.Challenge, await fx.TotpFor(u.Id))).Status);
    }

    [SqlFact]
    public async Task Totp_secret_is_encrypted_at_rest()
    {
        var (u, _) = await MfaUserAsync();
        var stored = await fx.Db(async d => (await d.Users.AsNoTracking().SingleAsync(x => x.Id == u.Id)).MfaSecretKey);
        Assert.StartsWith("v1:", stored);
        Assert.False(await fx.Db(d => d.Users.AnyAsync(x => x.PendingMfaSecret != null && x.Id == u.Id)));
    }

    [SqlFact]
    public async Task Enabling_requires_the_password_and_cannot_overwrite_an_existing_secret()
    {
        var c = fx.NewClient();
        var u = await fx.RegisterVerifiedAsync(c);
        var token = await fx.LoginTokenAsync(c, u);
        Assert.True((await Get(c, "/api/auth/mfa/setup", token)).Success);

        var noPassword = await Post(c, "/api/auth/mfa/enable", new { otpCode = await fx.TotpFor(u.Id), password = "not-the-password-1" }, token);
        Assert.Equal(HttpStatusCode.BadRequest, noPassword.Status);

        Assert.True((await Post(c, "/api/auth/mfa/enable", new { otpCode = await fx.TotpFor(u.Id), password = u.Password }, token)).Success);

        // an attacker holding only the access token cannot swap in their own authenticator
        Assert.Equal(HttpStatusCode.BadRequest, (await Get(c, "/api/auth/mfa/setup?forceMfaRegenerate=true", token)).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/mfa/enable", new { otpCode = "123456", password = u.Password }, token)).Status);
    }

    [SqlFact]
    public async Task Disabling_requires_password_and_code_then_ends_every_session()
    {
        var (u, c) = await MfaUserAsync();
        var login = await fx.LoginAsync(c, u);
        await fx.ClearTotpStep(u.Id);
        var done = await Verify(c, u, login.Challenge, await fx.TotpFor(u.Id));
        var token = done.Token!;

        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/mfa/disable", new { password = "wrong-password-1", otpCode = "123456" }, token)).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/mfa/disable", new { password = u.Password, otpCode = "000000" }, token)).Status);
        Assert.Contains((await Post(c, "/api/auth/mfa/disable", null, token)).Status, new[] { HttpStatusCode.BadRequest, HttpStatusCode.UnsupportedMediaType }); // old contract: token alone is no longer enough

        await fx.ClearTotpStep(u.Id);
        var off = await Post(c, "/api/auth/mfa/disable", new { password = u.Password, otpCode = await fx.TotpFor(u.Id) }, token);
        Assert.True(off.Success, off.Raw);

        Assert.Equal(HttpStatusCode.Unauthorized, (await Get(c, "/api/auth/user", token)).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/refresh-token", new { token = done.RefreshToken })).Status);
        var plain = await fx.LoginAsync(c, u);
        Assert.NotNull(plain.Token); // MFA really is off
        await fx.PumpAsync();
        Assert.NotNull(fx.Email.Last(u.Email, "turned off"));
    }

    [SqlFact]
    public async Task Admin_can_reset_another_users_mfa_but_ordinary_users_cannot()
    {
        var (victim, c) = await MfaUserAsync();
        var admin = await fx.RegisterVerifiedAsync(c, RoleType.Administrator);
        var adminToken = await fx.LoginTokenAsync(c, admin);
        var peer = await fx.RegisterVerifiedAsync(c);

        Assert.Equal(HttpStatusCode.Forbidden, (await Post(c, "/api/auth/mfa/admin/reset", new { email = victim.Email }, await fx.LoginTokenAsync(c, peer))).Status);
        Assert.True((await Post(c, "/api/auth/mfa/admin/reset", new { email = victim.Email }, adminToken)).Success);
        Assert.NotNull((await fx.LoginAsync(c, victim)).Token);
        Assert.True(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "mfa.admin_reset" && e.ActorUserId == admin.Id)));
    }

    // ---- email OTP ------------------------------------------------------------------------------------------

    [SqlFact]
    public async Task Email_otp_flow_requires_the_challenge_is_single_use_hashed_and_rate_limited()
    {
        var (u, c) = await MfaUserAsync();
        var login = await fx.LoginAsync(c, u);

        // cannot be used to spam an arbitrary address: needs a live challenge for that exact account
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/send-email-otp", new { email = u.Email, challengeToken = new string('z', 43) })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/send-email-otp", new { email = "someone-else@example.com", challengeToken = login.Challenge })).Status);

        Assert.True((await Post(c, "/api/auth/send-email-otp", new { email = u.Email, challengeToken = login.Challenge })).Success);
        Assert.Equal((HttpStatusCode)429, (await Post(c, "/api/auth/send-email-otp", new { email = u.Email, challengeToken = login.Challenge })).Status); // cooldown

        await fx.PumpAsync();
        var code = fx.OtpFromEmail(u.Email);
        Assert.NotNull(code);
        var stored = await fx.Db(async d => (await d.MfaChallenges.AsNoTracking().OrderByDescending(x => x.CreatedAt).FirstAsync(x => x.UserId == u.Id)).OtpHash);
        Assert.NotNull(stored);
        Assert.DoesNotContain(code!, stored);

        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, login.Challenge, code == "000000" ? "111111" : "000000", "Email")).Status);
        var ok = await Verify(c, u, login.Challenge, code!, "Email");
        Assert.True(ok.Success, ok.Raw);
        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, login.Challenge, code!, "Email")).Status); // single use
    }

    [SqlFact]
    public async Task An_email_code_is_not_accepted_as_a_totp_code_and_vice_versa()
    {
        var (u, c) = await MfaUserAsync();
        var login = await fx.LoginAsync(c, u);
        await Post(c, "/api/auth/send-email-otp", new { email = u.Email, challengeToken = login.Challenge });
        await fx.PumpAsync();
        var code = fx.OtpFromEmail(u.Email)!;
        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, login.Challenge, code, "Totp")).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Verify(c, u, login.Challenge, await fx.TotpFor(u.Id), "Email")).Status);
    }

    // ---- SMS OTP --------------------------------------------------------------------------------------------

    private async Task<string> EnrollPhoneAsync(HttpClient c, TestUser u, string phone)
    {
        var challenge = await fx.LoginAsync(c, u);
        await fx.ClearTotpStep(u.Id);
        var session = await Verify(c, u, challenge.Challenge, await fx.TotpFor(u.Id));
        await fx.ClearTotpStep(u.Id);

        var enroll = await Post(c, "/api/auth/mfa/sms/enroll", new { phoneNumber = phone, password = u.Password, otpCode = await fx.TotpFor(u.Id) }, session.Token);
        Assert.True(enroll.Success, enroll.Raw);
        await fx.PumpAsync();
        var code = fx.CodeFromSms(phone);
        Assert.NotNull(code);
        var confirm = await Post(c, "/api/auth/mfa/sms/confirm", new { code }, session.Token);
        Assert.True(confirm.Success, confirm.Raw);
        return phone;
    }

    [SqlFact]
    public async Task Sms_enrolment_verifies_ownership_and_sms_can_complete_login()
    {
        var (u, c) = await MfaUserAsync();
        var phone = "+4478" + Random.Shared.Next(10000000, 99999999);
        await EnrollPhoneAsync(c, u, phone);

        var login = await fx.LoginAsync(c, u);

        Console.WriteLine("LOGIN RESPONSE:");
        Console.WriteLine(login.Raw);

        Assert.Contains("\"sms\"", login.Raw);
        Assert.True((await Post(c, "/api/auth/mfa/send-sms-otp", new { email = u.Email, challengeToken = login.Challenge })).Success);
        await fx.PumpAsync();
        var code = fx.CodeFromSms(phone)!;
        var done = await Verify(c, u, login.Challenge, code, "Sms");
        Assert.True(done.Success, done.Raw);
        Assert.NotNull(done.Token);
    }

    [SqlFact]
    public async Task Sms_enrolment_requires_password_totp_and_e164_and_wrong_codes_are_limited()
    {
        var (u, c) = await MfaUserAsync();
        var login = await fx.LoginAsync(c, u);
        await fx.ClearTotpStep(u.Id);
        var token = (await Verify(c, u, login.Challenge, await fx.TotpFor(u.Id))).Token;

        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/mfa/sms/enroll", new { phoneNumber = "07911123456", password = u.Password, otpCode = "123456" }, token)).Status); // not E.164
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/mfa/sms/enroll", new { phoneNumber = "+447911123456", password = "wrong-password-1", otpCode = "123456" }, token)).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/mfa/sms/enroll", new { phoneNumber = "+447911123456", password = u.Password }, token)).Status); // MFA-protected account needs the TOTP

        await fx.ClearTotpStep(u.Id);
        Assert.True((await Post(c, "/api/auth/mfa/sms/enroll", new { phoneNumber = "+447911123456", password = u.Password, otpCode = await fx.TotpFor(u.Id) }, token)).Success);
        await fx.PumpAsync();
        var real = fx.CodeFromSms("+447911123456")!;
        var wrong = real == "000000" ? "111111" : "000000";
        for (var i = 0; i < 5; i++) Assert.Equal(HttpStatusCode.BadRequest, (await Post(c, "/api/auth/mfa/sms/confirm", new { code = wrong }, token)).Status);
        Assert.Equal((HttpStatusCode)429, (await Post(c, "/api/auth/mfa/sms/confirm", new { code = real }, token)).Status);
        Assert.Null(await fx.Db(async d => (await d.Users.AsNoTracking().SingleAsync(x => x.Id == u.Id)).PhoneVerifiedAt));
    }
}

public class TrustedDeviceFixture : ApiFixture
{
    protected override Dictionary<string, string?> Overrides() => new() { ["Security:TrustedDevices:Enabled"] = "true" };
}

[Trait("Category", "Integration")]
public class TrustedDeviceTests(TrustedDeviceFixture fx) : IClassFixture<TrustedDeviceFixture>
{
    private async Task<(TestUser U, HttpClient C, string Device)> TrustedAsync()
    {
        var c = fx.NewClient();
        var u = await fx.RegisterVerifiedAsync(c);
        await fx.EnableMfaAsync(c, u);
        var login = await fx.LoginAsync(c, u);
        await fx.ClearTotpStep(u.Id);
        var done = await Post(c, "/api/auth/mfa/verify", new { email = u.Email, otp = await fx.TotpFor(u.Id), method = "Totp", challengeToken = login.Challenge, trustThisDevice = true, deviceLabel = "My laptop" });
        Assert.True(done.Success, done.Raw);
        Assert.NotNull(done.TrustedDevice);
        return (u, c, done.TrustedDevice!);
    }

    [SqlFact]
    public async Task Trusted_device_skips_only_the_mfa_step_and_rotates_its_credential()
    {
        var (u, c, device) = await TrustedAsync();
        var stored = await fx.Db(d => d.TrustedDevices.AsNoTracking().Where(x => x.UserId == u.Id).Select(x => x.TokenHash).SingleAsync());
        Assert.NotEqual(device, stored); // hash only

        var wrongPassword = await fx.LoginAsync(c, u, device, "wrong-password-1");
        Assert.Equal(HttpStatusCode.BadRequest, wrongPassword.Status); // a trusted device never bypasses the password

        var ok = await fx.LoginAsync(c, u, device);
        Assert.NotNull(ok.Token);
        Assert.Null(ok.Challenge);
        Assert.NotNull(ok.TrustedDevice);
        Assert.NotEqual(device, ok.TrustedDevice);
    }

    [SqlFact]
    public async Task Replaying_a_rotated_device_credential_revokes_the_device()
    {
        var (u, c, device) = await TrustedAsync();
        var ok = await fx.LoginAsync(c, u, device);
        var rotated = ok.TrustedDevice!;

        var replay = await fx.LoginAsync(c, u, device); // the old credential again: a copy exists somewhere
        Assert.Null(replay.Token);
        Assert.NotNull(replay.Challenge);

        var afterReplay = await fx.LoginAsync(c, u, rotated); // the legitimate new credential is revoked as well
        Assert.Null(afterReplay.Token);
        Assert.True(await fx.Db(d => d.SecurityEvents.AnyAsync(e => e.EventType == "device.replay_detected" && e.UserId == u.Id)));
    }

    [SqlFact]
    public async Task A_device_credential_is_useless_for_another_user_and_cannot_be_revoked_by_one_either()
    {
        var (u, c, device) = await TrustedAsync();
        var (other, c2, otherDevice) = await TrustedAsync();

        Assert.Null((await fx.LoginAsync(c2, other, device)).Token); // cross-user misuse falls back to the MFA challenge

        var session = await fx.LoginAsync(c, u, device);
        Assert.Contains("My laptop", (await Get(c, "/api/auth/devices", session.Token)).Raw);
        var deviceId = await fx.Db(d => d.TrustedDevices.Where(x => x.UserId == u.Id).Select(x => x.Id).SingleAsync());

        var otherSession = await fx.LoginAsync(c2, other, otherDevice);
        Assert.Equal(HttpStatusCode.NotFound, (await Delete(c2, $"/api/auth/devices/{deviceId}", otherSession.Token)).Status); // not the owner

        Assert.True((await Delete(c, $"/api/auth/devices/{deviceId}", session.Token)).Success);
        var afterRevoke = await fx.LoginAsync(c, u, session.TrustedDevice);
        Assert.Null(afterRevoke.Token);
        Assert.NotNull(afterRevoke.Challenge);
    }

    [SqlFact]
    public async Task Administrators_never_receive_or_use_trusted_devices_and_password_change_revokes_devices()
    {
        var c = fx.NewClient();
        var admin = await fx.RegisterVerifiedAsync(c, RoleType.Administrator);
        await fx.EnableMfaAsync(c, admin);
        var login = await fx.LoginAsync(c, admin);
        await fx.ClearTotpStep(admin.Id);
        var done = await Post(c, "/api/auth/mfa/verify", new { email = admin.Email, otp = await fx.TotpFor(admin.Id), method = "Totp", challengeToken = login.Challenge, trustThisDevice = true });
        Assert.True(done.Success);
        Assert.Null(done.TrustedDevice);
        Assert.False(await fx.Db(d => d.TrustedDevices.AnyAsync(x => x.UserId == admin.Id)));

        var (u, c2, device) = await TrustedAsync();
        await Post(c2, "/api/auth/password-reset-request", new { email = u.Email });
        await fx.PumpAsync();
        var t = fx.TokenFromEmail(u.Email, "Reset");
        Assert.True((await Post(c2, "/api/auth/reset-password", new { email = u.Email, token = t, newPassword = "Brand-new-passphrase-42", confirmPassword = "Brand-new-passphrase-42" })).Success);
        var after = await fx.LoginAsync(c2, u, device, "Brand-new-passphrase-42");
        Assert.Null(after.Token);
        Assert.NotNull(after.Challenge);
    }
}
