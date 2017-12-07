using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;


public class siplog
{
    enum color { Green, Cyan, Red, Magenta, Yellow, DarkGreen, DarkCyan, DarkRed, DarkMagenta };

    static void Main(String[] arg)
    {
        try
        {
            List<string[]> messages = new List<string[]>();
            List<string[]> callLegs = new List<string[]>();          
            

            Console.Clear();
            if (Console.BufferWidth < 200) { Console.BufferWidth = 200; }
            Console.BackgroundColor = ConsoleColor.Black;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(@"           ____    ______   ____    ___                       ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(@"          /\  _`\ /\__  _\ /\  _`\ /\_ \                      ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"          \ \,\L\_\/_/\ \/ \ \ \L\ \//\ \     ___      __     ");
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine(@"           \/_\__ \  \ \ \  \ \ ,__/ \ \ \   / __`\  /'_ `\   ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"             /\ \L\ \ \_\ \__\ \ \/   \_\ \_/\ \L\ \/\ \L\ \  ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(@"             \ `\____\/\_____\\ \_\   /\____\ \____/\ \____ \ ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(@"              \/_____/\/_____/ \/_/   \/____/\/___/  \/___L\ \ ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"                                                       /\____/ ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"                                                       \_/__/  ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("Version 1.10                                          Greg Palmer");
            Console.WriteLine();
            if (arg.Length == 0)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\nNO FILES WERE SPECIFIED - Usage: siplog.exe logfile.log anotherlogfile.log ... ");
                Console.ForegroundColor = ConsoleColor.Gray;
                Environment.Exit(1);
            }
            messages = findmessages(arg);      //find SIP messages output to List<string[]> with 
                                               //  index start of msg[0], 
                                               //  date[1] 
                                               //  time[2]
                                               //  src IP[3]
                                               //  dst IP[4]
                                               //  first line of SIP msg[5] 
                                               //  Call-ID[6]
                                               //  To:[7]  
                                               //  From:[8]
                                               //  index end of msg[9]
                                               //  color [10]
                                               //  SDP [11]
                                               //  filename [12]
                                               //  SDP IP [13]
                                               //  SDP port [14]
                                               //  SDP codec [15]
                                               //  useragent or server[16]
                                              

            Console.WriteLine("sorting by date and time");
            messages = messages.OrderBy(theDate => theDate[1]).ThenBy(Time => Time[2]).ToList();  // sort by date then by time                    
            foreach (String[] line in messages)
            {
                if (line == null) { Console.Write("found null"); }
            }
            if (messages.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\nNo SIP messages were found.");
                Console.ForegroundColor = ConsoleColor.Gray;
                Environment.Exit(1);
            }
            callLegs = findCallLegs(messages);      //find all call legs
                                                    //  date [0]
                                                    //  time [1]
                                                    //  To: [2]
                                                    //  From: [3]B
                                                    //  Call-ID [4]
                                                    //  selected [5]
                                                    //  src ip [6]
                                                    //  dst ip [7]
                                                    //  filtered [8]
                                                    //  notify [9]
            if (callLegs.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\nNo Calls were found that start with an INVITE");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("Press any key to search SIP messages or press [esc] to quit");
                while (Console.ReadKey(true).Key != ConsoleKey.Escape)
                {
                    listallmsg(messages);
                    Console.WriteLine("Press any key to search SIP messages again or press [esc] to quit");
                }
                Environment.Exit(0);
            }
            callSelect(callLegs, messages);
        }
        catch (Exception ex)
        {
            Console.WriteLine("\nMessage ---\n{0}", ex.Message);
            Console.WriteLine(
                "\nHelpLink ---\n{0}", ex.HelpLink);
            Console.WriteLine("\nSource ---\n{0}", ex.Source);
            Console.WriteLine(
                "\nStackTrace ---\n{0}", ex.StackTrace);
            Console.WriteLine(
                "\nTargetSite ---\n{0}", ex.TargetSite);
        }
    }

    static List<string[]> findmessages(String[] arg)
    {
        Regex beginmsg = new Regex(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{6}.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");  //regex to match the begining of the sip message (if it starts with a date and has time and two IP addresses) 
        string requestRgxStr = @"ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}.*";
        string callidRgxStr = @"(?<!-.{8})(?<=Call-ID:).*";
        string toRgxStr = @"(?<=To:).*";
        string fromRgxStr = @"(?<=From:).*";
        string uaRgxStr = @"(?<=User-Agent:).*";
        string serverRgxStr = @"(?<=Server:).*";
        string portRgxStr = @"(?<=m=audio )\d*";
        string codecRgxStr = @"(?<=RTP\/AVP )\d*";
        string SDPIPRgxStr = @"(?<=c=IN IP4 )(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})";
        string mAudioRgxStr = @"m=audio \d* RTP\/AVP \d*";
        string occasRgxStr = @"(?<=Contact: ).*wlssuser";
        Regex requestRgx = new Regex(requestRgxStr);
        Regex callidRgx = new Regex(callidRgxStr);
        Regex toRgx = new Regex(toRgxStr);
        Regex fromRgx = new Regex(fromRgxStr);
        Regex uaRgx = new Regex(uaRgxStr);
        Regex serverRgx = new Regex(serverRgxStr);
        Regex portRgx = new Regex(portRgxStr);
        Regex codecRgx = new Regex(codecRgxStr);
        Regex SDPIPRgx = new Regex(SDPIPRgxStr);
        Regex mAudioRgx = new Regex(mAudioRgxStr);
        Regex occasRgx = new Regex(occasRgxStr);        
        List <string[]> outputlist = new List<string[]>();
        long progress = 0;
        bool IncludePorts = false;

        if (arg.Length == 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("\nNO FILES WERE SPECIFIED - Usage: siplog.exe logfile.log anotherlogfile.log ... ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Environment.Exit(1);
        }
        foreach (String file in arg)
        {
            if (!File.Exists(file) && !Regex.IsMatch(file, @"^-\w\b"))
            {
                Console.WriteLine("\nFile " + file + " does not exist ");
                Environment.Exit(1);
            }
            if (file == "-p")
            {
                IncludePorts = true;
            }
        }

        foreach (string file in arg)
        {
            if(!Regex.IsMatch(file, @"^-\w\b"))
            { 
                Console.WriteLine();
                long filelinecount = 0;
                //count the number of lines in a file
                using (StreamReader sr = new StreamReader(file))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        filelinecount++;
                        progress++;
                        if (progress == 10000)
                        {
                            Console.Write(".");
                            progress = 0;
                        }
                    }
                    sr.Close();
                }
                Console.WriteLine("\nReading " + filelinecount + " lines of File : " + file);
                Console.CursorTop = Console.CursorTop - 2;
                using (StreamReader sread = new StreamReader(file))
                {
                    string line = "";
                    for (int filelinenum = 0; filelinenum < filelinecount; filelinenum++)
                    {
                        progress++;
                        if (progress == 10000)
                        {
                            Console.Write("!");
                            progress = 0;
                        }
                        if (!string.IsNullOrEmpty(line) && beginmsg.IsMatch(line))
                        {
                            String[] outputarray = new String[17];
                            outputarray[0] = filelinenum.ToString(); // get the index of the start of the msg 
                            outputarray[1] = Regex.Match(line, @"(\d{4}-\d{2}-\d{2})").ToString();                             //date                                 
                            outputarray[2] = Regex.Match(line, @"(\d{2}:\d{2}:\d{2}.\d{6})").ToString();                       //time            
                            //src IP                                                                        
                            if (IncludePorts) { outputarray[3] = Regex.Match(line, @"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):\d*(?= >)").ToString(); }
                            else{ outputarray[3] = Regex.Match(line, @"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})").ToString(); }
                            //dst IP 
                            if (IncludePorts) { outputarray[4] = Regex.Match(line, @"(?<=> )(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):\d*").ToString(); }
                            else{ outputarray[4] = Regex.Matches(line, @"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")[1].ToString(); }    
                            line = sread.ReadLine();
                            filelinenum++;
                            //check to match these only once. no need match a field if it is already found
                            bool sipTwoDotOfound = false;
                            bool callidFound = false;
                            bool toFound = false;
                            bool fromFound = false;
                            bool SDPFopund = false;
                            bool SDPIPFound = false;
                            bool mAudioFound = false;
                            bool uaservfound = false;
                            while (!beginmsg.IsMatch(line)) //untill the begining of the next msg
                            {
                                if (!sipTwoDotOfound && requestRgx.IsMatch(line))
                                {
                                    outputarray[5] = requestRgx.Match(line).ToString().Trim();
                                    sipTwoDotOfound = true;
                                }
                                else if (!callidFound && callidRgx.IsMatch(line)) { outputarray[6] = callidRgx.Match(line).ToString().Trim(); callidFound = true; } // get call-id                    
                                else if (!toFound && toRgx.IsMatch(line)) { outputarray[7] = toRgx.Match(line).ToString().Trim(); toFound = true; } // get to:                    
                                else if (!fromFound && fromRgx.IsMatch(line)) { outputarray[8] = fromRgx.Match(line).ToString().Trim(); fromFound = true; } //get from                    
                                else if (!SDPFopund && line.Contains("Content-Type: application/sdp")) { outputarray[11] = " SDP"; SDPFopund = true; }
                                else if (!SDPIPFound && SDPIPRgx.IsMatch(line)) { outputarray[13] = SDPIPRgx.Match(line).ToString(); SDPIPFound = true; }
                                else if (!mAudioFound && mAudioRgx.IsMatch(line))
                                {
                                    outputarray[14] = portRgx.Match(line).ToString().Trim();
                                    outputarray[15] = codecRgx.Match(line).ToString().Trim();
                                    if (outputarray[15] == "0") { outputarray[15] = "G711u"; }
                                    if (outputarray[15] == "8") { outputarray[15] = "G711a"; }
                                    if (outputarray[15] == "9") { outputarray[15] = "G722"; }
                                    if (outputarray[15] == "18") { outputarray[15] = "G729"; }
                                    mAudioFound = true;
                                }
                                else if (!uaservfound && uaRgx.IsMatch(line))
                                {
                                    outputarray[16] = uaRgx.Match(line).ToString().Trim();
                                    uaservfound = true;
                                }
                                else if (!uaservfound && serverRgx.IsMatch(line))
                                {
                                    outputarray[16] = serverRgx.Match(line).ToString().Trim();
                                    uaservfound = true;
                                }
                                else if (!uaservfound && occasRgx.IsMatch(line))
                                {
                                    outputarray[16] = "occas";
                                }
                                if (filelinenum >= filelinecount) { break; }
                                else
                                {
                                    line = sread.ReadLine();
                                    filelinenum++;
                                }
                                progress++;
                                if (progress == 10000)
                                {
                                    Console.Write("!");
                                    progress = 0;
                                }
                            }
                            filelinenum--; // to counter the advancement of the for loop
                            outputarray[9] = filelinenum.ToString(); // get the index of the end of the msg*/
                            outputarray[10] = "ConsoleColor.Gray";
                            outputarray[12] = file; //add file name to dataset 
                            if (outputarray[5] == null) { outputarray[5] = "Invalid SIP characters"; }
                            if (sipTwoDotOfound) { outputlist.Add(outputarray); }
                        }
                        else
                        {
                            line = sread.ReadLine();
                        }
                    }
                    sread.Close();
                }
                Console.CursorTop = Console.CursorTop + 2;
            }
        }
        Console.WriteLine();
        return outputlist;
    }

    static List<string[]> findCallLegs(List<string[]> messagesinput)
    {
        bool getcallid = false;
        List<string[]> listout = new List<string[]>();
        for (int i = 0; i < messagesinput.Count; i++)
        {
            if (messagesinput[i][3] != messagesinput[i][4])
            {
                if (messagesinput[i][5].Contains("INVITE")|messagesinput[i][5].Contains("NOTIFY"))
                {
                    if (listout.Count > 0) // if it is not the first message
                    {
                        //check if call-id was not already gotten
                        for (int j = 0; j < listout.Count; j++)
                        {
                            getcallid = true;
                            if (listout[j][4] == messagesinput[i][6]) // check if re-invite
                            {
                                getcallid = false;
                                break;
                            }
                        }
                    }
                    else
                    {
                        getcallid = true;
                    }
                    if (getcallid == true)
                    {
                        // copy from msg input to arrayout
                        String[] arrayout = new String[10];
                        arrayout[0] = messagesinput[i][1] ?? String.Empty;//  date [0]
                        arrayout[1] = messagesinput[i][2] ?? String.Empty;//  time [1]
                        arrayout[2] = messagesinput[i][7] ?? String.Empty;//  To: [2]
                        arrayout[3] = messagesinput[i][8] ?? String.Empty;//  From: [3]
                        arrayout[4] = messagesinput[i][6] ?? String.Empty;//  Call-ID [4]
                        arrayout[5] = " ";                //  selected [5]  " " = not selected
                        arrayout[6] = messagesinput[i][3] ?? String.Empty;//  src IP [6]
                        arrayout[7] = messagesinput[i][4] ?? String.Empty;//  dst ip [7]
                        if (messagesinput[i][5].Contains("INVITE")) { arrayout[8] = "invite"; } else { arrayout[8] = ""; }
                        if (messagesinput[i][5].Contains("NOTIFY")) { arrayout[9] = "notify"; } else { arrayout[9] = ""; }
                        if (messagesinput[i][6] != null) { listout.Add(arrayout); }

                    }
                }
            }
        }
        return listout;
    }

    static void callDisplay(List<string[]> callLegs)
    {
        Console.Clear();
        Console.WindowWidth = Math.Min( 161, Console.LargestWindowWidth);
        Console.WindowHeight = Math.Min(44, Console.LargestWindowHeight);
        Console.BufferWidth = 200;
        Console.SetCursorPosition(0, 0);
        if (callLegs.Count > Console.WindowHeight)
        {
            Console.BufferHeight = 10 + callLegs.Count;
        }
        Console.WriteLine("[Spacebar] to select calls. [Enter] for call flow diagram. [F] to filter the calls. [S] to search all SIP msgs. [Esc] to quit. [N] to toggle NOTIFYs");
        Console.WriteLine("{0,-2} {1,-6} {2,-10} {3,-12} {4,-45} {5,-45} {6,-16} {7,-16}", "*", "index", "date", "time", "from:", "to:", "src IP", "dst IP");
        Console.WriteLine(new String('-', 160));
        int i = 0;
        foreach (String[] ary in callLegs)
        {
            if ((Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)) { break; }
            callline(ary, i);
            i++;
        }
    }

    static void callline(string[] InputCallLegs, int indx)
    {
        if (InputCallLegs[5] == "*") { Console.ForegroundColor = ConsoleColor.Cyan; }
        Console.WriteLine("{0,-2} {1,-6} {2,-10} {3,-12} {5,-45} {4,-45} {6,-16} {7,-17}"
            , InputCallLegs[5]
            , indx
            , InputCallLegs[0]
            , ((InputCallLegs[1]).Substring(0, 11)) ?? String.Empty
            , (InputCallLegs[2].Split('@')[0].Substring(0, Math.Min(44, InputCallLegs[2].Split('@')[0].Length))) ?? String.Empty
            , (InputCallLegs[3].Split('@')[0].Substring(0, Math.Min(44, InputCallLegs[3].Split('@')[0].Length))) ?? String.Empty
            , InputCallLegs[6] 
            , InputCallLegs[7] );
        Console.ForegroundColor = ConsoleColor.Gray;
    }

    static void callSelect(List<string[]> callLegs, List<string[]> messages)
    {
        int selected = 0;
        bool done = false;
        int position = 0;
        bool notify = false;
        String[] filter = new String[20];
        List<string[]> callLegsFiltered = new List<string[]>();
        for (int i = 0; i < callLegs.Count; i++)
        {
            if (callLegs[i][8] == "invite") { callLegsFiltered.Add(callLegs[i]); }
        }
        if (callLegsFiltered.Count == 0)
        {
            Console.WriteLine("No filtered Matches found. Press any key to continue");
            Console.ReadKey(true);
            return;
        }
        callDisplay(callLegsFiltered);
        Console.WriteLine("Number of SIP messages found : " + messages.Count);
        Console.WriteLine("Number of Call legs found : " + callLegs.Count);
        Console.WriteLine("Number of Call legs filtered : " + callLegsFiltered.Count);
        Console.SetCursorPosition(0, 0);
        Console.SetCursorPosition(0, 3);
        Console.BackgroundColor = ConsoleColor.DarkGray;
        Console.ForegroundColor = ConsoleColor.Black;
        callline(callLegsFiltered[position], position);
        Console.SetCursorPosition(0, 3);
        Console.BackgroundColor = ConsoleColor.Black;
        Console.ForegroundColor = ConsoleColor.Gray;
        while (done == false)
        {
            ConsoleKeyInfo keypressed = Console.ReadKey(true);
            if (keypressed.Key == ConsoleKey.DownArrow)
            {
                if (position < callLegsFiltered.Count - 1)
                {
                    Console.BackgroundColor = ConsoleColor.Black;  //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                    callline(callLegsFiltered[position], position);
                    position++;
                    Console.BackgroundColor = ConsoleColor.DarkGray;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = ConsoleColor.Black;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = ConsoleColor.Black;  //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                }
            }
            if (keypressed.Key == ConsoleKey.PageDown)
            {
                if (position + 40 < callLegsFiltered.Count - 1)
                {
                    Console.BackgroundColor = ConsoleColor.Black;  //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop += 39;
                    position += 40 ;
                    Console.BackgroundColor = ConsoleColor.DarkGray;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = ConsoleColor.Black;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = ConsoleColor.Black;  //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                }
                else
                {
                    Console.BackgroundColor = ConsoleColor.Black;  //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop = callLegsFiltered.Count - 1 + 3;
                    position = callLegsFiltered.Count - 1;
                    Console.BackgroundColor = ConsoleColor.DarkGray;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = ConsoleColor.Black;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = ConsoleColor.Black;  //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                }
            }
            if (keypressed.Key == ConsoleKey.UpArrow)
            {
                if (position > 0)
                {
                    Console.BackgroundColor = ConsoleColor.Black;  //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop -= 2;     //move cursor up two since writline advances one
                    position --;
                    Console.BackgroundColor = ConsoleColor.DarkGray;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = ConsoleColor.Black;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = ConsoleColor.Black; //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                }
                else
                {
                    Console.SetCursorPosition(0, 0);
                    Console.SetCursorPosition(0, 3);
                }
            }
            if (keypressed.Key == ConsoleKey.PageUp)
            {
                if (position  > 39)
                {
                    Console.BackgroundColor = ConsoleColor.Black;  //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop  -= 41;     //move cursor up two since writline advances one
                    position -= 40;
                    Console.BackgroundColor = ConsoleColor.DarkGray;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = ConsoleColor.Black;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = ConsoleColor.Black; //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                }
                else
                {
                    Console.BackgroundColor = ConsoleColor.Black;  //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop = 3;     //move cursor up two since writline advances one
                    position = 0;
                    Console.BackgroundColor = ConsoleColor.DarkGray;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = ConsoleColor.Black;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop -= 1;
                    Console.BackgroundColor = ConsoleColor.Black; //change the colors of the current postion to normal
                    Console.ForegroundColor = ConsoleColor.Gray;
                }
                if (position == 0)
                {
                    Console.SetCursorPosition(0, 0);
                    Console.SetCursorPosition(0, 3);
                }

            }
            if (keypressed.Key == ConsoleKey.Spacebar)
            {
                if (callLegsFiltered[position][5] == "*")
                {
                    callLegsFiltered[position][5] = " ";
                    selected--;
                    Console.BackgroundColor = ConsoleColor.DarkGray;
                    Console.ForegroundColor = ConsoleColor.Black;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop = Console.CursorTop - 1;
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.Gray;
                }
                else
                {
                    callLegsFiltered[position][5] = "*";
                    selected++;
                    Console.BackgroundColor = ConsoleColor.DarkGray;
                    Console.ForegroundColor = ConsoleColor.Black;
                    callline(callLegsFiltered[position], position);
                    Console.CursorTop = Console.CursorTop - 1;
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.Gray;
                }
            }
            if (keypressed.Key == ConsoleKey.Enter)
            {
                if (selected > 0)
                {
                    List<string[]> selectedmessages = new List<string[]>();
                    selectedmessages = selectMessages(messages, callLegsFiltered);  //find all messages of selected call legs
                    msgselect(selectedmessages);   //select SIP message from the call flow diagram                        
                    callDisplay(callLegsFiltered);
                    Console.WriteLine("Number of SIP messages found : " + messages.Count);
                    Console.WriteLine("Number of Call legs found : " + callLegs.Count);
                    Console.WriteLine("Number of Call legs filtered : " + callLegsFiltered.Count);
                    position = 0;
                    Console.SetCursorPosition(0, 0);
                    Console.SetCursorPosition(0, 3);
                    Console.BackgroundColor = ConsoleColor.Gray;
                    Console.ForegroundColor = ConsoleColor.Black;
                    callline(callLegsFiltered[position], position);
                    Console.SetCursorPosition(0, 3);
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.Gray;

                }
            }
            if (keypressed.Key == ConsoleKey.Escape)
            {
                Console.WriteLine("                                           ");
                Console.WriteLine("  +-------------------------------------+  ");
                Console.WriteLine("  |  Are you sure you wantto quit? Y/N? |  ");
                Console.WriteLine("  +-------------------------------------+  ");
                Console.WriteLine("                                           ");
                switch (Console.ReadKey(true).Key)
                {
                    case ConsoleKey.Y :
                        Console.Clear(); System.Environment.Exit(0);
                        break;
                    case ConsoleKey.N :
                        callDisplay(callLegsFiltered);
                        Console.WriteLine("Number of SIP messages found : " + messages.Count);
                        Console.WriteLine("Number of Call legs found : " + callLegs.Count);
                        Console.WriteLine("Number of Call legs filtered : " + callLegsFiltered.Count);
                        position = 0;
                        Console.SetCursorPosition(0, 0);
                        Console.SetCursorPosition(0, 3);
                        Console.BackgroundColor = ConsoleColor.Gray;
                        Console.ForegroundColor = ConsoleColor.Black;
                        callline(callLegsFiltered[position], position);
                        Console.SetCursorPosition(0, 3);
                        Console.BackgroundColor = ConsoleColor.Black;
                        Console.ForegroundColor = ConsoleColor.Gray;
                        break;
                }
            }   
            if (keypressed.Key == ConsoleKey.S)
            {
                do
                {
                    listallmsg(messages);
                    Console.WriteLine("Press any key to search SIP messages again or press [esc] to quit");
                } while (Console.ReadKey(true).Key != ConsoleKey.Escape);                    
                callDisplay(callLegsFiltered);
                Console.WriteLine("Number of SIP messages found : " + messages.Count);
                Console.WriteLine("Number of Call legs found : " + callLegs.Count);
                Console.WriteLine("Number of Call legs filtered : " + callLegsFiltered.Count);
                position = 0;
                Console.SetCursorPosition(0, 0);
                Console.SetCursorPosition(0, 3);
                Console.BackgroundColor = ConsoleColor.Gray;
                Console.ForegroundColor = ConsoleColor.Black;
                callline(callLegsFiltered[position], position);
                Console.SetCursorPosition(0, 3);
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Gray;
            }
            if (keypressed.Key == ConsoleKey.F)
            {
                callLegsFiltered.Clear();
                while (callLegsFiltered.Count == 0)
                {
                    Console.WriteLine("                                                                                                                          ");
                    Console.WriteLine("  +------------------------------------------------------------------------------------------------------------------------------------+  ");
                    Console.WriteLine("  | Enter space separated items like extensions, names or IP. Items are OR. Case sensitive. Leave blank for no Filter.                 |  ");
                    Console.WriteLine("  |                                                                                                                                    |  ");
                    Console.WriteLine("  +------------------------------------------------------------------------------------------------------------------------------------+  ");
                    Console.WriteLine("                                                                                                                          ");
                    Console.CursorTop -= 3;
                    Console.CursorLeft += 4;
                    filter = Console.ReadLine().Split(' ');
                    if (!string.IsNullOrEmpty(filter[0]))
                    {
                        for (int i = 0; i < callLegs.Count; i++)
                        {                            
                            for (int j = 0; j < callLegs[i].Length; j++)
                            {
                                String callitem = callLegs[i][j];
                                for(int k = 0; k < filter.Length; k++)
                                {
                                    if (callLegs[i][8] == "invite")
                                    {
                                        String filteritem = filter[k];
                                        if (callitem.Contains(filteritem)) { callLegsFiltered.Add(callLegs[i]); break; }
                                    }
                                    if (notify && callLegs[i][9] == "notify")
                                    {
                                        String filteritem = filter[k];
                                        if (callitem.Contains(filteritem)) { callLegsFiltered.Add(callLegs[i]); break; }
                                    }
                                }
                            }                            
                        }
                    }
                    else
                    {
                        for (int i = 0; i < callLegs.Count; i++)
                        {
                            if (callLegs[i][8] == "invite") { callLegsFiltered.Add(callLegs[i]); }
                        }
                    }
                    if (callLegsFiltered.Count == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.CursorTop = Console.CursorTop - 1;
                        Console.WriteLine("  | No calls found. Press any key to continue");
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.CursorVisible = true;
                        Console.ReadKey(true);
                        Console.CursorTop -= 4;
                    }
                }
                callDisplay(callLegsFiltered);
                Console.WriteLine("Number of SIP messages found : " + messages.Count);
                Console.WriteLine("Number of Call legs found : " + callLegs.Count);
                Console.WriteLine("Number of Call legs filtered : " + callLegsFiltered.Count);
                position = 0;
                Console.SetCursorPosition(0, 0);
                Console.SetCursorPosition(0, 3);
                Console.BackgroundColor = ConsoleColor.Gray;
                Console.ForegroundColor = ConsoleColor.Black;
                callline(callLegsFiltered[position], position);
                Console.SetCursorPosition(0, 3);
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Gray;
            }
            if (keypressed.Key == ConsoleKey.N)
            {
                callLegsFiltered.Clear();
                if (notify == false) { notify = true; } else { notify = false; }
                for (int i = 0; i < callLegs.Count; i++)
                {
                    if (callLegs[i][8] == "invite")
                    {
                        callLegsFiltered.Add(callLegs[i]); 
                    }
                    if (notify && callLegs[i][9] == "notify")
                    {
                        callLegsFiltered.Add(callLegs[i]); 
                    }
                }
                if (callLegsFiltered.Count == 0)
                {
                    Console.WriteLine("NO filtered matches found. Press any key to continue");
                    Console.ReadKey(true);
                    return;
                }
                callDisplay(callLegsFiltered);
                Console.WriteLine("Number of SIP messages found : " + messages.Count);
                Console.WriteLine("Number of Call legs found : " + callLegs.Count);
                Console.WriteLine("Number of Call legs filtered : " + callLegsFiltered.Count);
                position = 0;
                Console.SetCursorPosition(0, 0);
                Console.SetCursorPosition(0, 3);
                Console.BackgroundColor = ConsoleColor.Gray;
                Console.ForegroundColor = ConsoleColor.Black;
                callline(callLegsFiltered[position], position);
                Console.SetCursorPosition(0, 3);
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Gray;
            }
        }
        return;
    }

    static List<string[]> selectMessages(List<string[]> messages, List<string[]> callLegs)
    {
        List<string[]> outputlist = new List<string[]>();
        List<string> callids = new List<string>();
        color callcolor = color.Green;
        for (int i = 0; i < callLegs.Count; i++)
        {
            if (callLegs[i][5] == "*")
            {
                callids.Add(callLegs[i][4]);
            }
        }
        foreach (string cid in callids)
        {
            for (int i = 0; i < messages.Count; i++)
            {
                if (cid == messages[i][6])
                {
                    messages[i][10] = callcolor.ToString();
                }
            }
            if (callcolor == color.DarkMagenta) { callcolor = color.Green; } else { callcolor++; }
        }
        for (int i = 0; i < messages.Count; i++)
        {
            if (callids.Contains(messages[i][6]))
            {
                if (messages[i][3] != messages[i][4])
                {
                    outputlist.Add(messages[i]);
                }
            }
        }
        return outputlist;
    }

    static List<string> getips(List<string[]> selectedmessages)
    {
        List<string> ips = new List<string>();
        for (int i = 0; i < selectedmessages.Count; i++)
        {
            if (!ips.Contains(selectedmessages[i][3]))
            {
                ips.Add(selectedmessages[i][3]);
            }
            if (!ips.Contains(selectedmessages[i][4]))
            {
                ips.Add(selectedmessages[i][4]);
            }
        }
        return ips;
    }

    static void flow(List<string[]> selectedmessages, List<string> ips)
    {
        Console.Clear();
        if (selectedmessages.Count > Console.WindowHeight)
        {
            Console.BufferHeight = Math.Min(10 + selectedmessages.Count,Int16.MaxValue-1);
        }
        int width = 24;
        Console.Write(new String(' ', 17));
        foreach (string ip in ips)
        {
            width = width + 29;
            if (width > Console.WindowWidth)
            {
                Console.BufferWidth = Math.Min(15 + width, Int16.MaxValue - 1);
            }
            Console.Write(ip + new String(' ', 29 - ip.Length));
        }
        Console.WriteLine();
        Console.Write(new String(' ', 17));
        foreach (string ip in ips)
        {
            string ua = "";
            foreach (string[] ary in selectedmessages)
            {
                if (ary[3] == ip && ary[16] != null)
                {
                    ua = ary[16].Substring(0, Math.Min(15, ary[16].Length));
                    break;
                }
            }
            Console.Write(ua + new String(' ', 29 - ua.Length));
        }
        Console.WriteLine();
        Console.WriteLine(new String('-', width - 1));
        foreach (string[] msg in selectedmessages)
        {
            if ((Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)) { break; }
            messageline(msg, ips, false);
        }
        Console.WriteLine(new String('-', width - 1));
    }

    static void messageline(string[] message, List<string> ips, bool invert)
    {
        //get the index of the src and dst IP
        int srcindx = ips.IndexOf(message[3]);
        int dstindx = ips.IndexOf(message[4]);
        bool isright = false;
        int lowindx = 0;
        int hiindx = 0;
        string space = new String(' ', 28) + "|";
        if (srcindx < dstindx)
        {
            lowindx = srcindx;
            hiindx = dstindx;
            isright = true;
        }
        if (srcindx > dstindx)
        {
            lowindx = dstindx;
            hiindx = srcindx;
            isright = false;
        }
        if (invert)
        {
            Console.BackgroundColor = ConsoleColor.DarkGray;
            Console.ForegroundColor = ConsoleColor.Black;
        }
        else
        {
            Console.BackgroundColor = ConsoleColor.Black;
            Console.ForegroundColor = ConsoleColor.Gray;
        }
        Console.Write("{0,-10} {1,-12}|", message[1], message[2].Substring(0, 11));
        for (int i = 0; i < lowindx; i++)
        {
            Console.Write(space);
        }
        Console.ForegroundColor = (ConsoleColor)Enum.Parse(typeof(ConsoleColor), message[10]);
        if (isright) { Console.Write("-"); }
        else { Console.Write("<"); }
        string firstline = message[5].Replace("SIP/2.0 ", "");
        string displayedline = firstline.Substring(0, Math.Min(18, firstline.Length)) + message[11];
        int fullline = 29 * (hiindx - (lowindx + 1));
        double leftline = ((26 - displayedline.Length) + fullline) / 2; //
        Console.Write(new String('-', (int)Math.Floor(leftline)));
        Console.Write(displayedline);
        double rightline = 26 - leftline - displayedline.Length + fullline; //+25*(hiindx-lowindx+1)
        Console.Write(new String('-', (int)rightline));
        if (isright) { Console.Write(">"); }
        else { Console.Write("-"); }
        if (invert)
        {
            Console.BackgroundColor = ConsoleColor.DarkGray;
            Console.ForegroundColor = ConsoleColor.Black;
        }
        else
        {
            Console.BackgroundColor = ConsoleColor.Black;
            Console.ForegroundColor = ConsoleColor.Gray;
        }
        Console.Write("|");

        for (int i = 0; i < ips.Count - 1 - hiindx; i++)
        {
            Console.Write(space);
        }
        if (message[13] != null) { Console.Write(" {0}:{1} {2}", message[13], message[14], message[15]); }
        Console.BackgroundColor = ConsoleColor.Black;
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine();
    }

    static void msgselect(List<string[]> selectedmessages)
    {
        List<string> ips = new List<string>();
        ips = getips(selectedmessages); //get the IP addresses of the selected SIP messages for the top of the screen        
        int position = 0;

        Console.BackgroundColor = ConsoleColor.Black;
        Console.ForegroundColor = ConsoleColor.Gray;
        if (selectedmessages.Count > Console.BufferHeight) { Console.BufferHeight = Math.Min(selectedmessages.Count + 20, Int16.MaxValue - 1); }
        flow(selectedmessages, ips);  //display call flow Diaggram
        Console.SetCursorPosition(0, 0);   //brings window to the very top
        Console.SetCursorPosition(0, 3);
        messageline(selectedmessages[0], ips, true);
        Console.CursorTop -= 1;

        bool done = false;
        while (done == false)
        {
            ConsoleKeyInfo keypress = Console.ReadKey(true);
            if (keypress.Key == ConsoleKey.DownArrow)
            {
                if (position < selectedmessages.Count - 1)
                {
                    messageline(selectedmessages[position], ips, false);
                    position++;
                    messageline(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
            }
            if (keypress.Key == ConsoleKey.PageDown)
            {
                if (position + 40 < selectedmessages.Count - 1)
                {
                    messageline(selectedmessages[position], ips, false);
                    position += 40;
                    Console.CursorTop += 39;
                    messageline(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    messageline(selectedmessages[position], ips, false);
                    position = selectedmessages.Count - 1;
                    Console.CursorTop = selectedmessages.Count - 1 + 3;
                    messageline(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
            }
            if (keypress.Key == ConsoleKey.UpArrow)
            {
                if (position > 0)
                {
                    messageline(selectedmessages[position], ips, false);
                    Console.CursorTop -= 2;
                    position--;
                    messageline(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    Console.SetCursorPosition(0, 0);   //brings window to the very top
                    Console.SetCursorPosition(0, 3);
                }
            }
            if (keypress.Key == ConsoleKey.PageUp)
            {
                if (position > 39)
                {
                    messageline(selectedmessages[position], ips, false);
                    Console.CursorTop -= 41;
                    position -= 40;
                    messageline(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    messageline(selectedmessages[position], ips, false);
                    Console.CursorTop = 3;
                    position = 0;
                    messageline(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
                if (position == 0)
                {
                    Console.SetCursorPosition(0, 0);   //brings window to the very top
                    Console.SetCursorPosition(0, 3);
                }
            }
            if ((keypress.Key == ConsoleKey.Enter) || (keypress.Key == ConsoleKey.Spacebar))
            {
                displaymessage(position, selectedmessages);
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Gray;
                if (selectedmessages.Count > Console.BufferHeight) { Console.BufferHeight = Math.Min(selectedmessages.Count + 20, Int16.MaxValue - 1); }
                flow(selectedmessages, ips);  //display call flow Diaggram
                if (position == 0)
                {
                    Console.SetCursorPosition(0, 0);   //brings window to the very top
                    Console.SetCursorPosition(0, 3);
                    messageline(selectedmessages[0], ips, true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    Console.SetCursorPosition(0, (position > 17) ? position - 17 : 0);
                    Console.SetCursorPosition(0, position + 3);
                    messageline(selectedmessages[position], ips, true);
                    Console.CursorTop -= 1;
                }
            }
            if (keypress.Key == ConsoleKey.Escape)
            {
                done = true;
            }
        }
        return;
    }

    static void displaymessage(int msgindxselected, List<string[]> messages)
    {
        Console.Clear();
        if ((Int32.Parse(messages[msgindxselected][9]) - Int32.Parse(messages[msgindxselected][0])) > Console.BufferHeight)
        {
            Console.BufferHeight = Math.Min(5 + (Int32.Parse(messages[msgindxselected][9]) - Int32.Parse(messages[msgindxselected][0])), Int16.MaxValue - 1);
        }
        Console.WriteLine("From line " + messages[msgindxselected][0] + " to " + messages[msgindxselected][9] + " from file " + messages[msgindxselected][12]);
        using (StreamReader sr = new StreamReader(messages[msgindxselected][12]))
        {
            string line = "";
            Console.Write("Finding lines from file");
            long progress = 0;
            for (int i = 0; i < Int32.Parse(messages[msgindxselected][0]); i++)
            {
                progress++;
                if (progress == 10000)
                {
                    Console.Write(".");
                    progress = 0;
                }
                line = sr.ReadLine();
            }
            Console.WriteLine();
            Console.WriteLine(line);
            for (int j = Int32.Parse(messages[msgindxselected][0]); j < Int32.Parse(messages[msgindxselected][9]); j++)
            {
                Console.WriteLine(sr.ReadLine());
            }
            sr.Close();
        }
        Console.SetCursorPosition(0, 0);
        Console.ReadKey(true);
    }

    static void listallmsg(List<string[]> messages)
    {
        List<string[]> filtered = new List<string[]>();
        int maxline = 0;
        bool done = false;
        int position = 0;
        //string MsgLine;
        int MsgLineLen;
        Console.Clear();
        Console.BufferWidth = 500;
        Console.SetCursorPosition(0, 0);
        Console.WriteLine("Enter regex to search. Max lines displayed are 32765. example: for all the msg to/from 10.28.160.42 at 16:40:11 use 16:40:11.*10.28.160.42");
        Console.WriteLine("Data format: line number|date|time|src IP|dst IP|first line of SIP msg|From:|To:|Call-ID|line number|color|has SDP|filename|SDP IP|SDP port|SDP codec|useragent");
        string strginput = Console.ReadLine();
        Console.Clear();
        Console.SetCursorPosition(0, 0);
        if (string.IsNullOrEmpty(strginput))
        {
            Console.WriteLine("You must enter a regex");
            Console.ReadKey(true);
            done = true;
        }
        else
        {
            Regex regexinput = new Regex(strginput);
            foreach (string[] ary in messages)
            {
                if ((Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)) { break; }
                if (regexinput.IsMatch(string.Join(" ", ary)))
                {
                    //MsgLine = string.Join("|", ary); 
                    MsgLineLen = string.Join(" ", ary).Length + 28;
                    if (MsgLineLen >= Console.BufferWidth) { Console.BufferWidth = MsgLineLen+1; }
                    Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", ary);
                    filtered.Add(ary);
                    maxline++;
                    if (maxline > Console.BufferHeight) { Console.BufferHeight += maxline + 10; }
                    if (maxline > 32764) { break; }
                }
            }
            if (filtered.Count == 0)
            {
                Console.WriteLine("NO search matches found. Press any key to continue");
                Console.ReadKey(true);
                return;
            }
            Console.SetCursorPosition(0, 0);
            Console.BackgroundColor = ConsoleColor.DarkGray;
            Console.ForegroundColor = ConsoleColor.Black;
            Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
            Console.CursorTop -= 1;
            Console.BackgroundColor = ConsoleColor.Black;
            Console.ForegroundColor = ConsoleColor.Gray;
        }
        while (!done)
        {
            ConsoleKeyInfo keypressed = Console.ReadKey(true);
            switch (keypressed.Key)
            {
                case ConsoleKey.DownArrow:

                    if (position < filtered.Count - 1)
                    {
                        Console.BackgroundColor = ConsoleColor.Black;
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        position++;
                        Console.BackgroundColor = ConsoleColor.DarkGray;
                        Console.ForegroundColor = ConsoleColor.Black;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = ConsoleColor.Black;
                        Console.ForegroundColor = ConsoleColor.Gray;
                    }
                    break;

                case ConsoleKey.PageDown:

                    if (position + 40 < filtered.Count - 1)
                    {
                        Console.BackgroundColor = ConsoleColor.Black;
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        Console.CursorTop += 39;
                        position += 40;
                        Console.BackgroundColor = ConsoleColor.DarkGray;
                        Console.ForegroundColor = ConsoleColor.Black;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = ConsoleColor.Black;
                        Console.ForegroundColor = ConsoleColor.Gray;
                    }
                    break;

                case ConsoleKey.UpArrow:
                    if (position > 0)
                    {
                        Console.BackgroundColor = ConsoleColor.Black;
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        position--;
                        Console.CursorTop -= 2;
                        Console.BackgroundColor = ConsoleColor.DarkGray;
                        Console.ForegroundColor = ConsoleColor.Black;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = ConsoleColor.Black;
                        Console.ForegroundColor = ConsoleColor.Gray;
                    }
                    break;
                case ConsoleKey.PageUp:
                    if (position > 39)
                    {
                        Console.BackgroundColor = ConsoleColor.Black;
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        position-= 40;
                        Console.CursorTop -= 41;
                        Console.BackgroundColor = ConsoleColor.DarkGray;
                        Console.ForegroundColor = ConsoleColor.Black;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = ConsoleColor.Black;
                        Console.ForegroundColor = ConsoleColor.Gray;
                    }
                    break;

                case ConsoleKey.Enter:
                    displaymessage(position, filtered);
                    Console.Clear();
                    Console.BufferWidth = 500;
                    if (filtered.Count > Console.WindowHeight)
                    {
                        Console.BufferHeight = filtered.Count + 10;
                    }
                    Console.SetCursorPosition(0, 0);
                    foreach (string[] line in filtered)
                    {
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", line);
                    }
                    Console.SetCursorPosition(0, position);
                    Console.BackgroundColor = ConsoleColor.DarkGray;
                    Console.ForegroundColor = ConsoleColor.Black;
                    Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16}", filtered[position]);
                    Console.CursorTop = Console.CursorTop - 1;
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.Gray;
                    break;

                case ConsoleKey.Escape:
                    done = true;
                    break;
            }
        }
    }
}
