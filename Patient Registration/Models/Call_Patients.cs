using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Patient_Registration.Models
{
    public class Call_Patients
    {
        [Key]
        [Required]
        [Column(Order =1)]
        public int Id { get; set; }

        [Required]
        [Column(Order = 2)]
        [Display(Name = "Mobile No:")]
        public string MobileNo { get; set; }

        [Display(Name = "NIC:")]
        [Column(Order = 3)]
        public string? NIC { get; set; }

        [Display(Name = "Passport No:")]
        [Column(Order = 4)]
        public string? PassportNo { get; set; }

        [Required]
        [Display(Name = "Designation:")]
        [Column(Order = 5)]
        public string Designation { get; set; }

        [Required]
        [Display(Name = "Name:")]
        [Column(Order = 6)]
        public string Name { get; set; }

        [Display(Name = "Surname:")]
        [Column(Order = 7)]
        public string? Surname { get; set; }

        [Display(Name = "Full Name:")]
        [Column(Order = 8)]
        public string FullName { get; set; }

        [Required]
        [Display(Name = "Date Of Birth:")]
        [Column(Order = 9)]
        public string DOB { get; set; }

        [Required]
        [Display(Name = "Gender:")]
        [Column(Order = 10)]
        public string Gender { get; set; }

        [Column(Order = 11)]
        [Display(Name = "Resident Area:")]
        public string? ResidentArea { get; set; }

        [Column(Order = 12)]
        [Display(Name = "Nationality:")]
        public string? Nationality { get; set; }

        [Required]
        [Display(Name = "Religion:")]
        [Column(Order = 13)]
        public string Religion { get; set; }

        [Required]
        [Display(Name = "Guardian ID:")]
        [Column(Order = 14)]
        public int GuardianID { get; set; }

        [Required]
        [Display(Name = "Guardian Name:")]
        [Column(Order = 15)]
        public string GuardianName { get; set; }

        [Required]
        [Display(Name ="Relationship with Guardian:")]
        [Column(Order = 16)]
        public string RelationGuardian { get; set; }

        [Display(Name = "Loyalty No:")]
        [Column(Order = 17)]
        public string? LoyaltyNo { get; set; }

        [Display(Name = "Member ID:")]
        [Column(Order = 18)]
        public string? MemberID { get; set; }

        [EmailAddress]
        [Display(Name = "Email:")]
        [Column(Order = 19)]
        public string? Email { get; set; }

        [Display(Name = "Special Conditions:")]
        [Column(Order = 20)]
        public string? SpecialConditions { get; set; }

        [Display(Name = "Social Id:")]
        [Column(Order = 21)]
        public string? SocialId { get; set; }

        [Column(Order = 22)]
        public int? FamilyId { get; set; }

        //[Column(Order = 22)]
        //public string ImagePath { get; set; }

        [Column(Order = 23)]
        [Display(Name = "Loyalty Programme:")]
        public string? LoyaltyProgramId { get; set; }

        [Column(Order = 24)]
        [Display(Name = "Active:")]
        public bool Active { get; set; }
    }
}
