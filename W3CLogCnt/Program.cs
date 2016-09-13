using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Tx.Windows;
using W3;

/// <summary>
/// Program written by Jason Burton, for purpose of analyzing W3C log files for IP count output (CSV)
/// </summary>
namespace W3
{
    /// <summary>
    /// Generate Hit Information via Console
    /// </summary>
    class Program
    {
        private static string directory;
         
        /// <summary>
        /// By Jason Burton - jason@jbatlas.com 08-26-16
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            directory = AppDomain.CurrentDomain.BaseDirectory.ToString();
          
            System.IO.StreamReader file =  new System.IO.StreamReader(directory + "\\access.log");
            FileInfo fi = new FileInfo(directory + "\\access.log");


            IEnumerable<Tx.Windows.W3CEvent> evt = Tx.Windows.W3CEnumerable.FromFile(fi.FullName);

            //Gather the statistics
            var logfile = W3CEnumerable.FromFile(fi.FullName);

            //Using LINQ we output results accordingly.
            var l1 = (from r in logfile
                      orderby r.c_ip
                      group r by r.c_ip into grp
                      where grp.Key != null
                      select new { cnt = grp.Count(), key = grp.Key }).OrderByDescending(x => x.cnt);

            foreach (var w in l1)
            {
                if (w.key != null)
                {
                    Console.WriteLine(w.cnt + ",\"" + w.key + "\"");
                }

            }

            // Suspend the screen.
            Console.ReadLine();

        }

     






    }


}