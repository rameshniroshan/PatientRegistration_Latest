using Patient_Registration.Models;
using System.ComponentModel.DataAnnotations;

namespace Patient_Registration.ViewModels
{
    public class LoginViewModel
    {
        //[Required]
        //public string UserName { get; set; }

        //[Required]
        //public string Password { get; set; }

        public Call_Users usersdata { get; set; }
    }
}
