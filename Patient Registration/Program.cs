using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Patient_Registration.Data;
using Patient_Registration.Models;
using Patient_Registration.Services;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<RegisterDb>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("RegisterDb") ?? throw new InvalidOperationException("Connection string 'Patient_RegistrationContext' not found.")));


// Bind LdapSettings
builder.Services.Configure<LdapSettings>(builder.Configuration.GetSection("LdapSettings"));
// Add LDAP authentication service
builder.Services.AddScoped<LdapAuthenticationService>();


// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddSession(options =>
{
    options.Cookie.Name = ".AdventureWorks.Session";
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.IsEssential = true;
});

builder.Services.AddRazorPages();
builder.Services.AddHttpContextAccessor();


var app = builder.Build();
app.UseSession();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
app.UseStaticFiles();

app.UseRouting();
app.MapRazorPages();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Users}/{action=Signin}/{id?}");

app.Run();
