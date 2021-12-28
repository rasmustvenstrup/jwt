using System.Security.Claims;
using System.Text;
using JWT.Models;
using JWT.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Setup Swagger.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthorization(o =>
    {
        o.AddPolicy("AdminUsers", b => b.RequireClaim(ClaimTypes.Role, new[] { Role.Admin.ToString() }));
        o.AddPolicy("AllUsers", b => b.RequireClaim(ClaimTypes.Role, new[] { Role.Admin.ToString(), Role.User.ToString() }));
    }
);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(opt =>
{
    opt.TokenValidationParameters = new()
    {
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"])),
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"],
    };
});

builder.Services.AddSingleton<IUserService, UserService>();
builder.Services.AddSingleton<ITokenService, TokenService>();
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));

var app = builder.Build();

// Use Swagger.
app.UseSwagger();
app.UseSwaggerUI();

// Use authentication and authorization.
app.UseAuthentication();
app.UseAuthorization();


app.MapGet($"/users/authenticate/{{username}}", (string username, ITokenService tokenService) => GetToken(tokenService, username))
    .AllowAnonymous();

app.MapGet("/users", (IUserService userService) => userService.GetUsers())
    .RequireAuthorization("AllUsers");

app.MapPost("/users", ([FromBody] User user, IUserService userService) => userService.AddUser(user))
    .RequireAuthorization("AdminUsers");


app.Run();


IResult GetToken(ITokenService tokenService, string username)
{
    var token = tokenService.GetToken(username);
    return token == null ? Results.Unauthorized() : Results.Ok(token);
}