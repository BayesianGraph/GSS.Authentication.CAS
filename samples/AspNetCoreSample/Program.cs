using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using GSS.Authentication.CAS.AspNetCore;
using GSS.Authentication.CAS.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using NLog;
using NLog.Web;

var builder = WebApplication.CreateBuilder(args);
var logger = LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

builder.Services.AddRazorPages();
builder.Services.AddAuthorization(options =>
{
    // Globally Require Authenticated Users
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Events.OnSigningOut = context =>
        {
            var redirectContext = new RedirectContext<CookieAuthenticationOptions>(
                context.HttpContext,
                context.Scheme,
                context.Options,
                context.Properties,
                "/"
            );
            if (builder.Configuration.GetValue("Authentication:CAS:SingleSignOut", false))
            {
                // Single Sign-Out
                var casUrl = new Uri(builder.Configuration["Authentication:CAS:ServerUrlBase"]);
                var links = context.HttpContext.RequestServices.GetRequiredService<LinkGenerator>();
                var serviceUrl = context.Properties.RedirectUri ?? links.GetUriByPage(context.HttpContext, "/Index");
                redirectContext.RedirectUri = UriHelper.BuildAbsolute(
                    casUrl.Scheme,
                    new HostString(casUrl.Host, casUrl.Port),
                    casUrl.LocalPath, "/logout",
                    QueryString.Create("service", serviceUrl!));
            }

            context.Options.Events.RedirectToLogout(redirectContext);
            return Task.CompletedTask;
        };
    })
    .AddCAS(options =>
    {
        options.BackchannelTimeout = new TimeSpan(0, 10, 0);
        options.RemoteAuthenticationTimeout = new TimeSpan(0, 10, 0);
        options.CasServerUrlBase = builder.Configuration["Authentication:CAS:ServerUrlBase"];
        options.SaveTokens = builder.Configuration.GetValue("Authentication:CAS:SaveTokens", false);
        var protocolVersion = builder.Configuration.GetValue("Authentication:CAS:ProtocolVersion", 2);
        if (protocolVersion != 3)
        {
            options.ServiceTicketValidator = protocolVersion switch
            {
                1 => new Cas10ServiceTicketValidator(options),
                2 => new Cas20ServiceTicketValidator(options),
                _ => null
            };
        }
    
        options.Events.OnCreatingTicket = context =>
        {
            if (context.Identity == null)
                return Task.CompletedTask;
            // Map claims from assertion
            var assertion = context.Assertion;
            context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, assertion.PrincipalName));
            context.Identity.AddClaim(new Claim(ClaimTypes.Name, assertion.PrincipalName)); //This line allows you to access primary login info as User.identity.Name in cs code
            if (assertion.Attributes.TryGetValue("display_name", out var displayName))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.Name, displayName));
            }

            if (assertion.Attributes.TryGetValue("email", out var email))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.Email, email));
            }

            return Task.CompletedTask;
        };
        options.Events.OnRemoteFailure = context =>
        {
            var failure = context.Failure;
            if (!string.IsNullOrWhiteSpace(failure?.Message))
            {
                logger.Error(failure, "{Exception}", failure.Message);
            }

            context.Response.Redirect("/Account/ExternalLoginFailure");
            context.HandleResponse();
            return Task.CompletedTask;
        };

    });

// Setup NLog for Dependency injection
builder.Logging.ClearProviders().SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace);
builder.Host.UseNLog();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();
app.UseCookiePolicy();
app.MapRazorPages();

try
{
    app.Run();
}
catch (Exception exception)
{
    //NLog: catch setup errors
    logger.Error(exception, "Stopped program because of exception");
    throw;
}
finally
{
    // Ensure to flush and stop internal timers/threads before application-exit (Avoid segmentation fault on Linux)
    LogManager.Shutdown();
}