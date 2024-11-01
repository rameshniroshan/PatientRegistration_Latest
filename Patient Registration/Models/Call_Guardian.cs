using System.ComponentModel.DataAnnotations;

namespace Patient_Registration.Models
{
    public class Call_Guardian
    {
        [Key]
        [Required]
        public int Id { get; set; }

        [Required]
        public string MobileNo { get; set; }

        [Required]
        public String GuardianPatientName { get; set; }
    }
}
