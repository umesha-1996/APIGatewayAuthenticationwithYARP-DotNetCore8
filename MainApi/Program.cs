using Microsoft.AspNetCore.Authentication.BearerToken;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddReverseProxy()
	.LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

builder.Services.AddAuthentication(BearerTokenDefaults.AuthenticationScheme)
	.AddBearerToken();

builder.Services.AddAuthorization(options =>
{
	//defult policy
	options.AddPolicy("access", p => p.RequireAuthenticatedUser());

	//user policy
	options.AddPolicy("user-access", p => p.RequireAuthenticatedUser()
	.RequireClaim("role", "user"));

	//admin policy
	options.AddPolicy("admin-access", p => p.RequireAuthenticatedUser()
	.RequireClaim("role", "admin"));

});

var app = builder.Build();

app.UseHttpsRedirection();

//login endpoint
app.MapPost("/login", (string username, string password, string role = "user") =>
{
	if (username == "admin" && password == "admin")
	{
		//authenticate
		return Results.SignIn(new System.Security.Claims.ClaimsPrincipal(
			new ClaimsIdentity(
				[
				new Claim("id", Guid.NewGuid().ToString()),
				new Claim("ts", DateTime.UtcNow.ToShortDateString()),
				new Claim("sub", Guid.NewGuid().ToString()),
				new Claim("username", username),
				new Claim("role", role),
				], BearerTokenDefaults.AuthenticationScheme)),
				authenticationScheme: BearerTokenDefaults.AuthenticationScheme);
	}
	return Results.Unauthorized();
});

//registrationend point

app.UseAuthentication();
app.UseAuthorization();

app.MapReverseProxy();

app.Run();
