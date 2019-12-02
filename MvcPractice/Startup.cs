using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MvcPractice.Models;
using MvcPractice.Security;
using MvcPractice.TokenExpirationHandler;
using MvcPractice.Utilities;

namespace MvcPractice
{
    public class Startup
    {
        private IConfiguration _config;
        public Startup(IConfiguration configuration)
        {
            _config = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContextPool<AppDbContext>(options => options.UseSqlServer(_config.GetConnectionString("EmployeeDBConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>(options => {
                options.Password.RequiredLength = 5;
                options.Password.RequiredUniqueChars = 2;

                options.SignIn.RequireConfirmedEmail = true;

                options.Tokens.EmailConfirmationTokenProvider = "CustomEmailConfirmation";

                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);

            }).AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders()
            .AddTokenProvider<CustomEmailConfirmationTokenProvider<ApplicationUser>>("CustomEmailConfirmation");

            services.Configure<DataProtectionTokenProviderOptions>(options =>
            {
                options.TokenLifespan = TimeSpan.FromHours(5);
            });

            services.Configure<CustomEmailConfirmationTokenProviderOptions>(options =>
            {
                options.TokenLifespan = TimeSpan.FromDays(3);
            });

            services.AddAuthorization(options =>
            {
            options.AddPolicy("DeleteRolePolicy", policy =>
                                                  policy.RequireClaim("Delete Role", "true").
                                                  RequireClaim("Create Role", "true"));
                options.AddPolicy("EditRolePolicy", policy => 
                                                    policy.AddRequirements(new ManageAdminRolesAndClaimsRequirement()));
            });
            
            services.AddMvc(config => {
                var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
                config.Filters.Add(new AuthorizeFilter(policy));
                
            }).SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            services.AddAuthentication()
                .AddGoogle(options =>
                {
                    options.ClientId = "957315044662-d088q45flahi76nij0bi64g7isbfi8md.apps.googleusercontent.com";
                    options.ClientSecret = "X7yL-xZXRsQhOn56uJnm_ZWK";
                })
                .AddFacebook(options => 
                {
                    options.AppId = "952441171759145";
                    options.AppSecret = "f41e2c852eb182ea24c338e0125acb8e";
                });

            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Accounts/Login";  // to redirect user to login page if not authorize
                options.SlidingExpiration = true;
                options.AccessDeniedPath = "/Accounts/AccessDenied";
            });

            services.AddScoped<IEmployeeRepository, SQLEmployeeRepository>();
            services.AddSingleton<IAuthorizationHandler, CanEditOnlyOtherAdminRolesAndClaimsHandler>();
            services.AddSingleton<IAuthorizationHandler, SuperAdminHandler>();

            services.AddSingleton<DataProtectionPurposeStrings>();

            services.AddScoped<IEmailSenderService, EmailSenderService>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error"); // 500 internal server error handling
                app.UseStatusCodePagesWithReExecute("/Error/{0}"); // 404 error handling for page not found & employee not found
            }

            app.UseStaticFiles();

            app.UseAuthentication();
            
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

        }
        private bool AuthorizeAccess(AuthorizationHandlerContext context)
        {
            return context.User.IsInRole("Admin") && context.User.HasClaim("Edit Role", "true") || context.User.IsInRole("SuperAdmin");
        }
    }
}
