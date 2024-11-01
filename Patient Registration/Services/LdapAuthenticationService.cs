using System.DirectoryServices.Protocols;
using System.Net;
using Microsoft.Extensions.Options;
using Patient_Registration.Models;

namespace Patient_Registration.Services
{
    public class LdapAuthenticationService
    {
        private readonly LdapSettings _ldapSettings;
        public LdapAuthenticationService(IOptions<LdapSettings> ldapSettings)
        {
            _ldapSettings = ldapSettings.Value;
        }

        public bool Authenticate(string username, string password)
        {
            try
            {
                using (var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(_ldapSettings.Server, _ldapSettings.Port)))
                {
                    // Set credentials for LDAP bind
                    // var networkCredential = new NetworkCredential($"CN={username},{_ldapSettings.BaseDn}", password);
                    var networkCredential = new NetworkCredential(username, Uri.EscapeDataString(password));

                    // Attempt bind
                    ldapConnection.Bind();
                    return true;
                }
            }
            catch (LdapException ex)
            {
                return false;
            }
        }
    }
}
