using System;
using System.Collections.Generic;
using System.Data;

//using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Humanizer;
using Microsoft.AspNetCore.Components.Routing;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Patient_Registration.Data;
using Patient_Registration.Models;

namespace Patient_Registration.Controllers
{
    public class OurPatientsController : Controller
    {
        private readonly RegisterDb _context;

        public OurPatientsController(RegisterDb context)
        {
            _context = context;
        }

        //public class IdentityResult
        //{
        //    public int CurrentIdentity { get; set; }
        //}

        public async Task<IActionResult> GetGurdianNextId()
        {
            //        var currentIdentity = await _context.Call_Guardian
            //.FromSqlRaw("SELECT IDENT_CURRENT('YourTable') AS CurrentIdentity")
            //.Select( x => new IdentityResult { CurrentIdentity = (int)x.Id })
            //.FirstOrDefaultAsync();

            //var currentIdentity = await _context.Call_Guardian
            //    .FromSqlRaw("SELECT IDENT_CURRENT('Call_Guardian') AS CurrentIdentity").Select(x => new IdentityResult {CurrentIdentity });
            //    .Select( x => new IdentityResult { CurrentIdentity = (int)x.CurrentIdentity })
            //    .FirstOrDefaultAsync();

            //var currentIdentity = _context.Call_Guardian
            //                // .FromSqlRaw($"SELECT IDENT_CURRENT('Call_Guardian")
            //                 .FromSqlRaw($"SELECT top1 id from Call_Guardian")
            //                 .ToList();

            //using (var context = new LibraryContext())
            //{


            // FormattableString sql = $"SELECT * FROM Call_Guardian WHERE Id = '1'";
            //      var a = _context.Call_Guardian.FromSql(sql).FirstOrDefault();
            //}

            // var gurdianId = _context.Call_Guardian.FromSqlRaw<Call_Guardian>("SELECT id from Call_Guardian where id =1","").ToList();

           // var AA = _context.Call_Guardian.FromSql($"EXECUTE GetGuardianId");

            // var bb = _context.Call_Guardian.FromSqlRaw<Call_Guardian>("select * from Call_Guardian");

            var builder = WebApplication.CreateBuilder();
            String strConnString = builder.Configuration.GetConnectionString("RegisterDb").ToString();
            SqlConnection con = new SqlConnection(strConnString);
            SqlCommand cmd = new SqlCommand();
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.CommandText = "GetGuardianId";      
            cmd.Connection = con;
            con.Open();
            IDataReader reader = cmd.ExecuteReader();
            
            int GuardianId =0;
            while (reader.Read())
            {
                GuardianId = int.Parse(reader["lastGuardianId"].ToString());
                GuardianId += 1;
            }
            reader.Close();
            con.Close();

            return Content(GuardianId.ToString());
                
        }

        public string GetGurdianData(string searchtext)
        {
            string sOut =string.Empty;

            var nameList = _context.Call_Guardian.Where(p => p.GuardianPatientName.Contains(searchtext));

          dynamic Listview = new System.Dynamic.ExpandoObject();
            Listview.results = nameList;

            sOut = JsonConvert.SerializeObject(Listview, Formatting.None);

            //var patients = from g in _context.Call_Guardian.Where(g => g.GuardianPatientName.Contains(searchtext))
            //               select g.GuardianPatientName;


            return sOut;
        }


        //public async Task<IActionResult> SearchByPatientName(string searchtext)
        //{
        //    implement like search function




        //    var patients = from p in _context.Call_Patients
        //                   select p;

        //    if (!string.IsNullOrEmpty(searchtext))
        //    {
        //        patients = patients.Where(p => p.Name.Contains(searchtext) || p.Surname.Contains(searchtext));
        //    }

        //    //string sOut = string.Empty;

        //    //var listByName = _context.Call_Patients.Where(p => p.Name.Contains(searchtext));

        //    //dynamic Listview = new System.Dynamic.ExpandoObject();
        //    //Listview.results = listByName;

        //    //sOut = JsonConvert.SerializeObject(Listview, Formatting.None);

        //    //var patients = from g in _context.Call_Guardian.Where(g => g.GuardianPatientName.Contains(searchtext))
        //    //               select g.GuardianPatientName;


        //    return RedirectToAction("Create", await patients.ToListAsync());
        //}

        //public string GetAllGurdianNames()
        //{
        //    string sOut = string.Empty;
        //    var getAllNameList = _context.Call_Guardian.Select(g => g.GuardianPatientName);
        //    dynamic Listview = new System.Dynamic.ExpandoObject();
        //    Listview.results = getAllNameList;
        //    sOut = JsonConvert.SerializeObject(Listview, Formatting.None);
        //    return sOut;
        //}

        public string GetAllPatientsMobile()
        {
            string sOut = string.Empty;
            var getAllMobileList = _context.Call_Patients.Select(g => g.MobileNo).Distinct();
            dynamic Listview = new System.Dynamic.ExpandoObject();
            Listview.mobileList = getAllMobileList;          

            sOut = JsonConvert.SerializeObject(Listview, Formatting.None);
            return sOut;
        }

        public string GetAllLoyaltyProgramme()
        {
            string sOut = string.Empty;
            //var getAllLoyaltyProgramm = _context.Call_LoyaltyPrograms.Select(g => g.LoyaltyName);

            var getAllLoyaltyProgramm = from p in _context.Call_LoyaltyPrograms
                           select p;

            dynamic Listview = new System.Dynamic.ExpandoObject();
            Listview.loyaltyProgramme = getAllLoyaltyProgramm.Where(p => p.Active == "true");
            sOut = JsonConvert.SerializeObject(Listview, Formatting.None);
            return sOut;
        }

        public string GetAllPatientsName()
        {
            string sOut = string.Empty;
            var getAllNameList = _context.Call_Patients.Where(x=>x.Active == true).Select(g => g.Name + " " + g.Surname);
            dynamic Listview = new System.Dynamic.ExpandoObject();
            Listview.nameList = getAllNameList;

            sOut = JsonConvert.SerializeObject(Listview, Formatting.None);
            return sOut;
        }

        public string GetAllPatientsGuardians()
        {
            string sOut = string.Empty;
            var getAllGuardianList = _context.Call_Patients.Select(g => g.GuardianName).Distinct();
            dynamic Listview = new System.Dynamic.ExpandoObject();
            Listview.guardiansname = getAllGuardianList;

            sOut = JsonConvert.SerializeObject(Listview, Formatting.None);
            return sOut;
        }

        // GET: Patients/Create
        public async Task<IActionResult> Create()
        {
            var sessionValue = HttpContext.Session.GetString("loggeduser");
            if ((sessionValue == "none") || (sessionValue == null))
            {
                return RedirectToAction("Signin","Users");
            }
            else
            {
                return View(await _context.Call_Patients.Where(x => x.Active == true).ToListAsync());
            }

        }

        [HttpPost]
        public async Task<IActionResult> Create(Call_Patients call_Patients)
        {
            Call_Patients patients = new Call_Patients();
            patients.MobileNo = call_Patients.MobileNo;
            patients.NIC = call_Patients.NIC;
            patients.PassportNo = call_Patients.PassportNo;
            patients.Designation = call_Patients.Designation;
            patients.Name = call_Patients.Name;
            patients.Surname = call_Patients.Surname;
            patients.FullName = call_Patients.Name + " " + call_Patients.Surname;
            patients.DOB = call_Patients.DOB;
            patients.Gender = call_Patients.Gender;
            patients.ResidentArea = call_Patients.ResidentArea;
            patients.Nationality = call_Patients.Nationality;
            patients.Religion = call_Patients.Religion;
            patients.GuardianID = call_Patients.GuardianID;
            patients.GuardianName = call_Patients.GuardianName;
            patients.RelationGuardian = call_Patients.RelationGuardian;
            patients.LoyaltyNo = call_Patients.LoyaltyNo;
            patients.MemberID = call_Patients.MemberID;
            patients.Email = call_Patients.Email;
            patients.SpecialConditions = call_Patients.SpecialConditions;
            patients.SocialId = call_Patients.SocialId;
            patients.FamilyId = call_Patients.FamilyId;
            patients.LoyaltyProgramId = call_Patients.LoyaltyProgramId;
            patients.Active = call_Patients.Active;
            _context.Add(patients);

            if (call_Patients.RelationGuardian == "Self")
            {
                Call_Guardian gurdian = new Call_Guardian();
                gurdian.MobileNo = call_Patients.MobileNo;
                gurdian.GuardianPatientName = call_Patients.Name + " " + call_Patients.Surname;
                _context.Add(gurdian);                
            }
             await _context.SaveChangesAsync();

            HttpContext.Session.SetString("patientCreated", "true");

            //return View(await _context.Call_Patients.ToListAsync());
            return View(await _context.Call_Patients.Where(x => x.Active == true).ToListAsync());
        }

        public async Task<IActionResult> Search(string? mobile,string? name,string? guardianName)
        {
            var patients = from p in _context.Call_Patients
                           select p;

           
            if (!string.IsNullOrEmpty(mobile) || (!string.IsNullOrEmpty(name)) || (!string.IsNullOrEmpty(guardianName)))
            {
                //patients = patients.Where(p => p.Name.Contains(name) || p.Surname.Contains(name) || p.MobileNo.Contains(mobile) || p.GuardianName.Contains(guardianName));
                patients = patients.Where(p => p.FullName.Contains(name) || p.MobileNo.Contains(mobile) || p.GuardianName.Contains(guardianName));
            }
           

            //if (!string.IsNullOrEmpty(searchTerm))
            //{
            //    patients = patients.Where(p => p.Name.Contains(searchTerm) || p.Surname.Contains(searchTerm) || p.GuardianID.ToString() == searchTerm || p.MobileNo.Contains(searchTerm));
            //}

            return View("Create",await patients.Where(x => x.Active == true).ToListAsync());
        }
                       

        [HttpGet]
        public async Task<IActionResult> Edit(int Id)
        {
            if (Id <= 0)
            {
                return NotFound();
            }
            var call_Patients = _context.Call_Patients.FirstOrDefault(p => p.Id == Id);
            if (call_Patients == null)
            {
                return NotFound();
            }

            return View(call_Patients);
        }

        [HttpPost]
        public async Task<IActionResult> Edit(Call_Patients call_Patients)
        {
            var patient = _context.Call_Patients.FirstOrDefault<Call_Patients>(p => p.Id == call_Patients.Id);
            
            if (patient == null)
            {
                return NotFound();
            }

            patient.NIC = call_Patients.NIC;
            patient.PassportNo = call_Patients.PassportNo;
            patient.Designation = call_Patients.Designation;
            patient.Name = call_Patients.Name;
            patient.Surname = call_Patients.Surname;
            patient.ResidentArea = call_Patients.ResidentArea;
            patient.Nationality = call_Patients.Nationality;
            patient.Religion = call_Patients.Religion;
            patient.RelationGuardian = call_Patients.RelationGuardian;
            patient.GuardianID = call_Patients.GuardianID;
            patient.GuardianName = call_Patients.GuardianName;
            patient.LoyaltyNo = call_Patients.LoyaltyNo;
            patient.MemberID = call_Patients.MemberID;
            patient.Email = call_Patients.Email;
            patient.SpecialConditions = call_Patients.SpecialConditions;
            patient.SocialId = call_Patients.SocialId;
            patient.FamilyId = call_Patients.FamilyId;
            patient.LoyaltyProgramId = call_Patients.LoyaltyProgramId;
            patient.Active = call_Patients.Active;
            _context.Update(patient);
            await _context.SaveChangesAsync();

            return View("Create",await _context.Call_Patients.Where(x=>x.Active == true).ToListAsync());
        }


        // GET: Patients/Details/5
        public async Task<IActionResult> Details(int id)
        {
            if (id <= 0)
            {
                return NotFound();
            }

            var call_Patients = await _context.Call_Patients
                .FirstOrDefaultAsync(m => m.Id == id);
            if (call_Patients == null)
            {
                return NotFound();
            }

            return View(call_Patients);
        }

       

        // GET: Patients/Delete/5
        public async Task<IActionResult> Delete(int id)
        {
            if (id <= 0)
            {
                return NotFound();
            }

            var call_Patients = await _context.Call_Patients
                .FirstOrDefaultAsync(m => m.Id == id);
            if (call_Patients == null)
            {
                return NotFound();
            }

            return View(call_Patients);
        }

        // POST: OurPatients/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var call_Patients = await _context.Call_Patients.FindAsync(id);
            if (call_Patients != null)
            {
               call_Patients.Active = false;
                _context.Update(call_Patients);
                _context.SaveChanges();
                //_context.Call_Patients.Remove(call_Patients);
            }

          //  await _context.SaveChangesAsync();
            return RedirectToAction("create");
        }


        // GET: Patients/Create
        public async Task<IActionResult> InactivePatients()
        {    
            var sessionValue = HttpContext.Session.GetString("loggeduser");
            if ((sessionValue == "none") || (sessionValue == null))
            {
                    return RedirectToAction("Signin", "Users");
                }
            else
            {
               return View(await _context.Call_Patients.Where(x => x.Active == false).ToListAsync());
            }
        }

        public async Task<IActionResult> InactiveDetails(int id)
        {
            if (id <= 0)
            {
                return NotFound();
            }

            var call_Patients = await _context.Call_Patients
                .FirstOrDefaultAsync(m => m.Id == id);
            if (call_Patients == null)
            {
                return NotFound();
            }

            return View(call_Patients);
        }

        [HttpGet]
        public async Task<IActionResult> InactiveEdit(int Id)
        {
            if (Id <= 0)
            {
                return NotFound();
            }
            var call_Patients = _context.Call_Patients.FirstOrDefault(p => p.Id == Id);
            if (call_Patients == null)
            {
                return NotFound();
            }

            return View(call_Patients);
        }

        [HttpPost]
        public async Task<IActionResult> InactiveEdit(Call_Patients call_Patients)
        {
            var patient = _context.Call_Patients.FirstOrDefault<Call_Patients>(p => p.Id == call_Patients.Id);

            if (patient == null)
            {
                return NotFound();
            }

            patient.NIC = call_Patients.NIC;
            patient.PassportNo = call_Patients.PassportNo;
            patient.Designation = call_Patients.Designation;
            patient.Name = call_Patients.Name;
            patient.Surname = call_Patients.Surname;
            patient.ResidentArea = call_Patients.ResidentArea;
            patient.Nationality = call_Patients.Nationality;
            patient.Religion = call_Patients.Religion;
            patient.RelationGuardian = call_Patients.RelationGuardian;
            patient.GuardianID = call_Patients.GuardianID;
            patient.GuardianName = call_Patients.GuardianName;
            patient.LoyaltyNo = call_Patients.LoyaltyNo;
            patient.MemberID = call_Patients.MemberID;
            patient.Email = call_Patients.Email;
            patient.SpecialConditions = call_Patients.SpecialConditions;
            patient.SocialId = call_Patients.SocialId;
            patient.FamilyId = call_Patients.FamilyId;
            patient.LoyaltyProgramId = call_Patients.LoyaltyProgramId;
            patient.Active = call_Patients.Active;
            _context.Update(patient);
            await _context.SaveChangesAsync();

            return View("InactivePatients", await _context.Call_Patients.Where(x => x.Active == false).ToListAsync());
        }


        //public async Task<IActionResult> Index(string searchTerm)
        //{
        //    var patients = from p in _context.Call_Patients
        //                   select p;

        //    if (!string.IsNullOrEmpty(searchTerm))
        //    {
        //        patients = patients.Where(p => p.Name.Contains(searchTerm) || p.FamilyId.ToString().Contains(searchTerm) || p.MobileNo.Contains(searchTerm));
        //    }

        //    return View(await patients.ToListAsync());
        //}








        //// GET: OurPatients
        //public async Task<IActionResult> Index()
        //{
        //    return View(await _context.Call_Patients.ToListAsync());
        //}

        //// GET: OurPatients/Details/5
        //public async Task<IActionResult> Details(string id)
        //{
        //    if (id == null)
        //    {
        //        return NotFound();
        //    }

        //    var call_Patients = await _context.Call_Patients
        //        .FirstOrDefaultAsync(m => m.MobileNo == id);
        //    if (call_Patients == null)
        //    {
        //        return NotFound();
        //    }

        //    return View(call_Patients);
        //}

        //// GET: OurPatients/Create
        //public IActionResult Create()
        //{
        //    return View();
        //}

        //// POST: OurPatients/Create
        //// To protect from overposting attacks, enable the specific properties you want to bind to.
        //// For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        //[HttpPost]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> Create([Bind("MobileNo,NIC,PassportNo,Designation,Name,Surname,DOB,Gender,ResidentArea,Nationality,Religion,GuardianID,GuardianName,RelationGuardian,LoyaltyNo,MemberID,Email,SpecialConditions,SocialId,FamilyId")] Call_Patients call_Patients)
        //{
        //    if (ModelState.IsValid)
        //    {
        //        _context.Add(call_Patients);
        //        await _context.SaveChangesAsync();
        //        return RedirectToAction(nameof(Index));
        //    }
        //    return View(call_Patients);
        //}

        //// GET: OurPatients/Edit/5
        //public async Task<IActionResult> Edit(string id)
        //{
        //    if (id == null)
        //    {
        //        return NotFound();
        //    }

        //    var call_Patients = await _context.Call_Patients.FindAsync(id);
        //    if (call_Patients == null)
        //    {
        //        return NotFound();
        //    }
        //    return View(call_Patients);
        //}

        //// POST: OurPatients/Edit/5
        //// To protect from overposting attacks, enable the specific properties you want to bind to.
        //// For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        //[HttpPost]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> Edit(string id, [Bind("MobileNo,NIC,PassportNo,Designation,Name,Surname,DOB,Gender,ResidentArea,Nationality,Religion,GuardianID,GuardianName,RelationGuardian,LoyaltyNo,MemberID,Email,SpecialConditions,SocialId,FamilyId")] Call_Patients call_Patients)
        //{
        //    if (id != call_Patients.MobileNo)
        //    {
        //        return NotFound();
        //    }

        //    if (ModelState.IsValid)
        //    {
        //        try
        //        {
        //            _context.Update(call_Patients);
        //            await _context.SaveChangesAsync();
        //        }
        //        catch (DbUpdateConcurrencyException)
        //        {
        //            if (!Call_PatientsExists(call_Patients.MobileNo))
        //            {
        //                return NotFound();
        //            }
        //            else
        //            {
        //                throw;
        //            }
        //        }
        //        return RedirectToAction(nameof(Index));
        //    }
        //    return View(call_Patients);
        //}

        //// GET: OurPatients/Delete/5
        //public async Task<IActionResult> Delete(string id)
        //{
        //    if (id == null)
        //    {
        //        return NotFound();
        //    }

        //    var call_Patients = await _context.Call_Patients
        //        .FirstOrDefaultAsync(m => m.MobileNo == id);
        //    if (call_Patients == null)
        //    {
        //        return NotFound();
        //    }

        //    return View(call_Patients);
        //}

        //// POST: OurPatients/Delete/5
        //[HttpPost, ActionName("Delete")]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> DeleteConfirmed(string id)
        //{
        //    var call_Patients = await _context.Call_Patients.FindAsync(id);
        //    if (call_Patients != null)
        //    {
        //        _context.Call_Patients.Remove(call_Patients);
        //    }

        //    await _context.SaveChangesAsync();
        //    return RedirectToAction(nameof(Index));
        //}

        //private bool Call_PatientsExists(string id)
        //{
        //    return _context.Call_Patients.Any(e => e.MobileNo == id);
        //}
    }
}
