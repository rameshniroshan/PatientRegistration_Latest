using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion.Internal;
using Patient_Registration.Data;
using Patient_Registration.Models;
using Patient_Registration.ViewModels;
using Microsoft.Extensions.Configuration;
using System.Diagnostics.Eventing.Reader;
using Novell.Directory.Ldap;
using Patient_Registration.Services;
using System.Security;
using System.Text;
//using LdapConnection = System.DirectoryServices.Protocols.LdapConnection;
//using LdapConnection = Novell.Directory.Ldap.LdapConnection;
namespace Patient_Registration.Controllers
{
    public class UsersController : Controller
    {
        private readonly RegisterDb _context;
        private readonly IConfiguration _configuration;
        private readonly LdapAuthenticationService _ldapAuthService;
        public UsersController(RegisterDb context, IConfiguration configuration, LdapAuthenticationService ldapAuthService)
        {
            _context = context;
            _configuration = configuration;
            _ldapAuthService = ldapAuthService;
        }

        public ActionResult Dashboard()
        {
            var sessionValue = HttpContext.Session.GetString("loggeduser");
            if (sessionValue != "none")
            {
                return View();
            }
            return View("Signin");
        }
        public ActionResult Signin()
        {
            return View();
            
        }
        public ActionResult Logout()
        {
            HttpContext.Session.SetString("loggeduser", "none");
            //return View("Signin");
            return RedirectToAction("Signin", "Users");
        }

        [HttpPost]
        public ActionResult Signin(Call_Users ur)
        {            
            SecureString securePassword = new SecureString();
            foreach(char c in ur.Password)
            {
                securePassword.AppendChar(c);
            }
            securePassword.MakeReadOnly();
            
            bool isAuthenticated = _ldapAuthService.Authenticate(ur.UserName, @ur.Password);
            if (isAuthenticated)
            {
                try
                {
                    HttpContext.Session.SetString("loggeduser", ur.UserName);
                    return RedirectToAction("Create", "OurPatients");
                }
                catch (Exception ex)
                {
                    return View();
                }
            }
            else
            {
                ViewBag.Error = "Invalid username or password";
                return View();
            }           
            
        }

        [HttpPost]
        public ActionResult Signinnn(Call_Users ur)
        {
            var ldapSettings = _configuration.GetSection("LdapSettings");
            string ldapServer = ldapSettings["Server"].ToString();
            int ldapPort = int.Parse(ldapSettings["Port"]);
            //  string baseDn = ldapSettings["BaseDn"];
            string loginDN = "uid=NN3056,ou=system";
            try
            {
                //-----------------------------------------

                //LdapConnection conn = new  LdapConnection();
                //conn.Connect(ldapServer, ldapPort);
                //conn.Bind(loginDN, "123@Intel");
                //-------------------------------------------

                //--------------------------------------
                //var connection = new LdapConnection(new LdapDirectoryIdentifier(ldapServer, ldapPort))
                //{
                //    AuthType = AuthType.Negotiate,
                //    Credential = new("NN3056", "123@Intel")
                //};
                //connection.SessionOptions.ProtocolVersion = 3;
                //connection.Bind();

                //-------------------------------------

                 // Set up LDAP directory identifier
                 var ldapIdentifier = new LdapDirectoryIdentifier(ldapServer, ldapPort);
                 // Initialize the LDAP connection
                 using (var ldapConnection = new System.DirectoryServices.Protocols.LdapConnection(ldapIdentifier))
                 {
                     ldapConnection.SessionOptions.ProtocolVersion = 3;
                     ldapConnection.SessionOptions.SecureSocketLayer = ldapServer.StartsWith("ldaps://");

                     // Bypass server certificate validation for testing purposes only
                     ldapConnection.SessionOptions.VerifyServerCertificate += (sender, certificate) => true;

                     // Use fully qualified distinguished name if needed
                     // var credentials = new NetworkCredential("ldap://203.143.31.74:6688/" + "NN3056", "123@Intel");
                     var credentials = new NetworkCredential("NN3056", "123@Intel");

                     ldapConnection.AuthType = AuthType.Basic;

                     // Attempt to bind/authenticate with the LDAP server
                     ldapConnection.Bind(credentials);
                 }

                /* using (var ldapConnection = new System.DirectoryServices.Protocols.LdapConnection(new LdapDirectoryIdentifier(ldapServer, ldapPort)))
                 {
                     ldapConnection.SessionOptions.SecureSocketLayer = true;
                     ldapConnection.AuthType = AuthType.Basic;
                     var credentials = new NetworkCredential(ur.UserName, ur.Password);
                     ldapConnection.Bind(credentials);  // Authenticate with LDAP
                 }*/

                /*var ldapIdentifier = new LdapDirectoryIdentifier(ldapServer, ldapPort);
                 using (var ldapConnection = new LdapConnection(ldapIdentifier))
                 {
                     //ldapConnection.SessionOptions.SecureSocketLayer = ldapServer.StartsWith("ldaps://"); // Enable SSL if needed
                     ldapConnection.AuthType = AuthType.Basic;

                     // Add domain prefix if required
                     var credentials = new NetworkCredential("LDAP:\\192.168.100.200\\" + ur.UserName, ur.Password);
                     ldapConnection.Bind(credentials);  // Authenticate with LDAP

                 }*/

                /*var remoteIpAddress = HttpContext.Connection.RemoteIpAddress;
                string allowedIpAddress = "192.168.100.22";*/
                // string domain = "http://localhost:5094/";

                /* var url = HttpContext.Request.GetDisplayUrl();
                 // Extract the domain
                 var domain = new Uri(url).Host;*/

                //**********************************
                /* if (remoteIpAddress != null && remoteIpAddress.ToString() == allowedIpAddress)
                 {
                     if((ur.UserName == "NN3056") && (ur.Password == "123@Intel"))
                     {
                         HttpContext.Session.SetString("loggeduser", ur.UserName);
                         return RedirectToAction("Create", "OurPatients");
                     }
                 }/*

                //**********************************

                //------------------------------------
                // Perform DNS lookup
               /* var ipAddresses = Dns.GetHostAddresses(domain);

                // Retrieve the IP address of the request
                var remoteIpAddress = HttpContext.Connection.RemoteIpAddress;
                if (remoteIpAddress != null && ipAddresses.Any(ip => ip.ToString() == remoteIpAddress.ToString()))
                {
                    // Proceed if the IP matches
                }
                else
                {
                    // Handle unauthorized access
                    return Unauthorized("Unauthorized IP address.");
                }/*

                //--------------------------------------

                */

                /* var user = _context.Call_Users.FirstOrDefault(x => x.UserName == ur.UserName && x.Password == ur.Password);
                 if (user != null)
                 {

                     HttpContext.Session.SetString("loggeduser", user.UserName);

                     // return View("Dashboard", user);
                     return RedirectToAction("Create", "OurPatients");
                 }*/
            }
            catch (Exception ex)
            {

            }
            ViewBag.Error = "Invalid username or password";
            return View();
        }

        // GET: Users
        public IActionResult ChangePassword()
        {
            var sessionValue = HttpContext.Session.GetString("loggeduser");
            if ((sessionValue == "none") || (sessionValue == null))
            {
                return RedirectToAction("Signin", "Users");
            }
            else
            {
                return View();
            }
            /*var username = HttpContext.Session.GetString("loggeduser");
            if (!string.IsNullOrEmpty(username))
            {
                var user = _context.Call_Users.FirstOrDefault(x => x.UserName == username);

            }*/

        }

        [HttpPost]
        public IActionResult ChangePassword(string? oldpwd, string? newpwd,string? confirmnewpwd)
        {
            var username = HttpContext.Session.GetString("loggeduser");
            
            if (!string.IsNullOrEmpty(username))
            {
                 var usr = _context.Call_Users.FirstOrDefault(x => x.UserName == username);
                if(usr != null)
                {
                    if(usr.Password == oldpwd)
                    {
                        if (!string.IsNullOrEmpty(newpwd))
                        {
                            if (newpwd.Equals(confirmnewpwd))
                            {
                                usr.Password = newpwd;
                                _context.Update(usr);
                                _context.SaveChanges();
                                HttpContext.Session.SetString("loggeduser", "none");
                                return View("Signin");
                            }
                            else
                            {
                                ViewBag.Error = "New password and Confirm password are mismatch";
                            }
                        }
                    }
                    else
                    {
                        ViewBag.Error = "Invalid previous password";
                    }
                }
            }
            return View();
        }

        // GET: Users
        public async Task<IActionResult> Index()
        {
            return View(await _context.Call_Users.ToListAsync());
        }

        // GET: Users/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_Users = await _context.Call_Users
                .FirstOrDefaultAsync(m => m.UserId == id);
            if (call_Users == null)
            {
                return NotFound();
            }

            return View(call_Users);
        }

        // GET: Users/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Users/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("UserId,UserName,Password,Active,Type")] Call_Users call_Users)
        {
            if (ModelState.IsValid)
            {
                _context.Add(call_Users);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(call_Users);
        }

        // GET: Users/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_Users = await _context.Call_Users.FindAsync(id);
            if (call_Users == null)
            {
                return NotFound();
            }
            return View(call_Users);
        }

        // POST: Users/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("UserId,UserName,Password,Active,Type")] Call_Users call_Users)
        {
            if (id != call_Users.UserId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(call_Users);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!Call_UsersExists(call_Users.UserId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(call_Users);
        }

        // GET: Users/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_Users = await _context.Call_Users
                .FirstOrDefaultAsync(m => m.UserId == id);
            if (call_Users == null)
            {
                return NotFound();
            }

            return View(call_Users);
        }

        // POST: Users/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var call_Users = await _context.Call_Users.FindAsync(id);
            if (call_Users != null)
            {
                _context.Call_Users.Remove(call_Users);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool Call_UsersExists(int id)
        {
            return _context.Call_Users.Any(e => e.UserId == id);
        }
    }
}
