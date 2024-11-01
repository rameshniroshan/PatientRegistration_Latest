namespace Patient_Registration.Models
{
    public class LdapSettings
    {
        public string Server { get; set; }
        public int Port { get; set; }
        public string BaseDn { get; set; }
        //public string AdminDn { get; set; }
        //public string AdminPassword { get; set; }
    }
}
