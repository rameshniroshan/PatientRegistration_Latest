using System.ComponentModel.DataAnnotations;

namespace Patient_Registration.Models
{
    public class Call_Users
    {
        [Key]
        [Required]
        public int UserId { get; set; }
        public string UserName { get; set; }

        public string Password { get; set; }

        public bool Active { get; set; }
        public int Type { get; set; }
    }
}
