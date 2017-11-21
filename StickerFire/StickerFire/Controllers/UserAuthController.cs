using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using StickerFire.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace StickerFire.Controllers
{
    public class UserAuthController : Controller
    {

        //Dependancy injection for userManager and signInManager
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger _logger;


        //Constuctor with dependancies
        public UserAuthController(UserManager<ApplicationUser> usermanager, SignInManager<ApplicationUser> signInManager, ILogger<UserAuthController> logger)
        {
            _userManager = usermanager;
            _signInManager = signInManager;
            _logger = logger;
        }


        //Regular user signup/registration page
        [HttpGet]
        public IActionResult Index(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }


        //Register regular user
        [HttpPost]
        public async Task<IActionResult> Register(MegaViewModel rvm, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {

                var user = new ApplicationUser { UserName = rvm.RegisterViewModel.Email, Email = rvm.RegisterViewModel.Email };
                var result = await _userManager.CreateAsync(user, rvm.RegisterViewModel.Password);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index", "Home");
                }
            }
            return RedirectToAction("Index", "UserAuth");
        }


        //External Registration -- OAuth
        public IActionResult ExternalLogin(string provider, string returnURL = null)
        {
            var redirectURL = Url.Action(nameof(ExternalLoginCallback), "UserAuth", new { returnURL });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectURL);
            return Challenge(properties, provider);
        }


        //External Login Callback, this redirects to home page if OAuth is succesful or to external login if 
        public async Task<IActionResult> ExternalLoginCallback(string returnURL = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                return RedirectToAction(nameof(Login));
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();

            if (info == null)
            {
                return RedirectToAction(nameof(Login));
            }

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                return RedirectToAction("Index", "Home");
            }

            if (result.IsLockedOut)
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                return View("ExternalLogin", new ExternalLoginModel { Email = email });
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    throw new ApplicationException("Error loading external login information during confirmation.");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await _userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                        return RedirectToAction("Index", "Home");
                    }
                }
                return View();
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View(nameof(ExternalLogin), model);
        }


        //Admin Registration form
        [Authorize(Policy = "Admin Only")]
        [HttpGet]
        public IActionResult RegisterAdmin(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }


        //Register Admin user
        [Authorize(Policy = "Admin Only")]
        [HttpPost]
        public async Task<IActionResult> RegisterAdmin(MegaViewModel avm, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = avm.RegisterViewModel.Email, Email = avm.RegisterViewModel.Email };
                var result = await _userManager.CreateAsync(user, avm.RegisterViewModel.Password);
                
                //If user is created correctly, assign them and admin role
                if (result.Succeeded)
                {
                    List<Claim> memberClaims = new List<Claim>();

                    Claim admin = new Claim(ClaimTypes.Role, "Admin", ClaimValueTypes.String);
                    memberClaims.Add(admin);

                    var addClaims = await _userManager.AddClaimsAsync(user, memberClaims);

                    //Sign in the new administrator
                    if (addClaims.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);

                        return RedirectToAction("Index", "Home");
                    }
                }
            }
            return View();
        }


        //Login User
        [HttpPost]
        public async Task<IActionResult> Login(MegaViewModel lvm)
        {
            if (ModelState.IsValid)
            {
                //bind viewmodel data to user and sign in.
                var result = await _signInManager.PasswordSignInAsync(lvm.LoginViewModel.Email, lvm.LoginViewModel.Password, lvm.LoginViewModel.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    var userIdentity = new ClaimsIdentity("Registration");

                    var userPrinciple = new ClaimsPrincipal(userIdentity);
                    await HttpContext.SignInAsync(
                        "CookieLogin", userPrinciple,
                            new AuthenticationProperties
                            {
                                ExpiresUtc = DateTime.UtcNow.AddMinutes(45),
                                IsPersistent = false,
                                AllowRefresh = false

                            });

                    return RedirectToAction("Index", "Home");
                }

            }
            string error = "Unable to log you in.  Please try again or contact your system admin.";
            ModelState.AddModelError("", error);
            return RedirectToAction("Index", "UserAuth");
        }


        //Logout the User
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

    }
}
