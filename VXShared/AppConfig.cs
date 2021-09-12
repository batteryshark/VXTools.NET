using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace VXShared
{

    class ConfigEntry
    {
        public String name { get; set; }
        public String map { get; set; }
        public String executable { get; set; }
        public String args { get; set; }
        public String cwd { get; set; }

        public string[] envar { get; set; }
        public string[] preload { get; set; }
    }

    class AppConfig
    {
        public String name;
        public String map;
        public String executable;
        public String args;
        public String cwd;
        public String[] envar;
        public String[] preload;
        public Boolean valid;

        void PrintInfo()
        {
            Console.WriteLine("---------");
            Console.WriteLine("Config Info: ");
            Console.WriteLine("Name: " + this.name);
            Console.WriteLine("Map File: " + this.map);
            Console.WriteLine("Executable: " + this.executable);
            Console.WriteLine("Args: " + this.args);
            Console.WriteLine("Cwd: " + this.cwd);
            Console.WriteLine("Envars: ");
            foreach (String ev in this.envar)
            {
                Console.WriteLine(ev);
            }

            Console.WriteLine("Preload: ");
            foreach (String pl in this.preload)
            {
                Console.WriteLine(pl);
            }
        }
        public AppConfig(String path_to_app, String selected_config)
        {
            valid = false;
            String path_to_vxconfig_file = Path.Combine(path_to_app, "vxapp.config");
            if (!File.Exists(path_to_vxconfig_file)) { return; }

            String config_text = File.ReadAllText(path_to_vxconfig_file);
            List<ConfigEntry> config_entries = JsonSerializer.Deserialize<List<ConfigEntry>>(config_text);
            
            foreach (var entry in config_entries)
            {

                // Hack to support blank config selections (first entry).
                if (selected_config == "")
                {
                    selected_config = entry.name;
                }
                if (entry.name == selected_config)
                {
                    this.name = entry.name;
                    this.map = entry.map;
                    this.executable = entry.executable;
                    this.args = entry.args;
                    this.cwd = entry.cwd;
                    this.envar = entry.envar;
                    this.preload = entry.preload;
                }
            }
            if (this.name == "") { Console.WriteLine("Error - Config Not Found."); return; }
            this.valid = true;
            return;
        }
    }
}
