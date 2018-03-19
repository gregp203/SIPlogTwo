using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Net;

public class SiplogTWO
{
    //tcpdump -i any -nn -A -tttt port 5060
    /*
    string GwAddrRgxStr = @"(?<=Sent:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}-\d{2}:\d{2} Recv:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}-\d{2}:\d{2}).*\[.*\].*\[.*\]\h(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"; //for AudioCodes 1st group is ip address
    string farEndRgxStr = @"(?<= Outgoing SIP Message to | Incoming SIP Message from )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"; //for AudioCodes
    string directionRgxStr = @"(Outgoing|Incoming)(?= SIP Message (to|from))"; //for AudioCodes
    string beginMsgRgxStr = @"\)\s*New SIPMessage created\s-"; //for AudioCodes
    string dateRgxStr = @"(?<=Sent:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}-\d{2}:\d{2} Recv:)\d{4}-\d{2}-\d{2}"; //for AudioCodes
    string timeRgxStr = @"(?<=Sent:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}-\d{2}:\d{2} Recv:\d{4}-\d{2}-\d{2}T)\d{2}:\d{2}:\d{2}\.\d{3}-\d{2}:\d{2}"; //for AudioCodes
    string endMsgRgxStr = @"Sent:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}-\d{2}:\d{2} Recv:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}-\d{2}:\d{2}"; // for AudioCodes
    */
    string beginMsgRgxStr = @"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{6}.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"; //regex to match the begining of the sip message (if it starts with a date and has time and two IP addresses)  for tcpdumpdump
    string dateRgxStr = @"(\d{4}-\d{2}-\d{2})"; //for tcpdumpdump
    string timeRgxStr = @"(\d{2}:\d{2}:\d{2}.\d{6})"; //for tcpdumpdump
    string srcIpPortRgxStr = @"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(:|.)\d*(?= >)";
    string srcIpRgxStr = @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?=(.|:)\d* >)";
    string dstIpPortRgxStr = @"(?<=> )(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(:|.)\d*";
    string dstIpRgxStr = @"(?<=> )(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})";
    string requestRgxStr = @"ACK.*SIP\/2\.0|BYE.*SIP\/2\.0|CANCEL.*SIP\/2\.0|INFO.*SIP\/2\.0|INVITE.*SIP\/2\.0|MESSAGE.*SIP\/2\.0|NOTIFY.*SIP\/2\.0|OPTIONS.*SIP\/2\.0|PRACK.*SIP\/2\.0|PUBLISH.*SIP\/2\.0|REFER.*SIP\/2\.0|REGISTER.*SIP\/2\.0|SUBSCRIBE.*SIP\/2\.0|UPDATE.*SIP\/2\.0|SIP\/2\.0 \d{3}(\s*\w*)";
    string callidRgxStr = @"(?<!-.{8})(?<=Call-ID:).*";//do not match if -Call-ID instead of Call-ID
    string toRgxStr = @"(?<=To:) *(\x22.+\x22)? *<?(sip:)([^@>]+)";
    string fromRgxStr = @"(?<=From:) *(\x22.+\x22)? *<?(sip:)([^@>]+)";
    string uaRgxStr = @"(?<=User-Agent:).*";
    string serverRgxStr = @"(?<=Server:).*";
    string portRgxStr = @"(?<=m=audio )\d*";
    string codecRgxStr = @"(?<=RTP\/AVP )\d*";
    string SDPIPRgxStr = @"(?<=c=IN IP4 )(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})";
    string mAudioRgxStr = @"m=audio \d* RTP\/AVP \d*";
    string occasRgxStr = @"(?<=Contact: ).*wlssuser";
    string cseqRgxStr = @"CSeq:\s?(\d{1,3})\s?(\w*)";
    Regex beginmsgRgx;
    Regex dateRgx;
    Regex timeRgx;
    Regex srcIpPortRgx;
    Regex srcIpRgx;
    Regex dstIpPortRgx;
    Regex dstIpRgx;
    Regex requestRgx;
    Regex callidRgx;
    Regex toRgx;
    Regex fromRgx;
    Regex uaRgx;
    Regex serverRgx;
    Regex portRgx;
    Regex codecRgx;
    Regex SDPIPRgx;
    Regex mAudioRgx;
    Regex occasRgx;
    Regex cseqRgx;
    static readonly object _locker = new object();
    enum CallLegColors { Green, Cyan, Red, Magenta, Yellow, DarkGreen, DarkCyan, DarkRed, DarkMagenta };
    enum AttrColor : short { Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, Darkyellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White, }
    String[,] sortFields;
    bool IncludePorts;
    List<string> streamData = new List<string>();
    List<string[]> messages = new List<string[]>();
    //  index start of msg[0] 
    //  date[1] 
    //  time[2]
    //  src IP[3]
    //  dst IP[4]
    //  Request/Method line of SIP msg[5] 
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
    //  CSeq [17]
    List<string[]> callLegs = new List<string[]>();
    //  date [0]
    //  time [1]
    //  To: [2]
    //  From: [3]
    //  Call-ID [4]
    //  selected [5]
    //  src ip [6]
    //  dst ip [7]
    //  filtered [8]
    //  method(invite,notify,registraion,supscription) [9]
    String[] filter;
    List<string[]> callLegsDisplayed = new List<string[]>(); // filtered call legs where [8] == filtered 
    List<string[]> selectedmessages = new List<string[]>();  // call legs  where [5] == selected 
    List<string> IPsOfIntrest = new List<string>();   // all the IP addresses from the selectedmessages
    List<string> callIDsOfIntrest = new List<string>(); // all the callIDs from the selectedmesages 
    int CallInvites;
    int notifications;
    int registrations;
    int subscriptions;
    int callLegsDisplayedCountPrev;
    int prevNumSelectdIPs;
    int prevNumSelectMsg;
    int IPprevNumSelectMsg;
    int numSelectedCalls;
    bool filterChange = false;
    StreamReader fileSread;
    long currentFileLoadLeng;
    long currentFileLoadProg;
    bool fileReadDone = false;
    AttrColor statusBarTxtClr;
    AttrColor statusBarBkgrdClr;
    AttrColor headerTxtClr;
    AttrColor headerBkgrdClr;
    ConsoleColor fieldConsoleTxtClr;
    ConsoleColor fieldConsoleBkgrdClr;
    ConsoleColor fieldConsoleTxtInvrtClr;
    ConsoleColor fieldConsoleBkgrdInvrtClr;
    ConsoleColor fieldConsoleSelectClr;
    ConsoleColor msgBoxTxt;
    ConsoleColor msgBoxBkgrd;
    AttrColor fieldAttrTxtClr;
    AttrColor fieldAttrTxtInvrtClr;
    AttrColor fieldAttrBkgrdClr;
    AttrColor fieldAttrBkgrdInvrtClr;
    AttrColor fieldAttrSelectClr;
    AttrColor footerTxtClr;
    AttrColor footerBkgrdClr;
    AttrColor sortTxtdClr;
    AttrColor sortBkgrdClr;
    int[] fakeCursor = new int[2];
    int flowWidth;
    string methodDisplayed;
    string displayMode;
    bool showNotify;
    int CallListPosition;
    int callsDisplaysortIdx;
    bool dupIP;
    int flowSelectPosition;
    StreamWriter flowFileWriter;
    bool writeFlowToFile;
    bool htmlFlowToFile;

    public SiplogTWO()
    {
        Regex.CacheSize = 20;
        beginmsgRgx = new Regex(beginMsgRgxStr, RegexOptions.Compiled);
        dateRgx = new Regex(dateRgxStr, RegexOptions.Compiled);
        timeRgx = new Regex(timeRgxStr, RegexOptions.Compiled);
        srcIpPortRgx = new Regex(srcIpPortRgxStr, RegexOptions.Compiled);
        srcIpRgx = new Regex(srcIpRgxStr, RegexOptions.Compiled);
        dstIpPortRgx = new Regex(dstIpPortRgxStr, RegexOptions.Compiled);
        dstIpRgx = new Regex(dstIpRgxStr, RegexOptions.Compiled);
        requestRgx = new Regex(requestRgxStr, RegexOptions.Compiled);
        callidRgx = new Regex(callidRgxStr, RegexOptions.Compiled);
        toRgx = new Regex(toRgxStr, RegexOptions.Compiled);
        fromRgx = new Regex(fromRgxStr, RegexOptions.Compiled);
        uaRgx = new Regex(uaRgxStr, RegexOptions.Compiled);
        serverRgx = new Regex(serverRgxStr, RegexOptions.Compiled);
        portRgx = new Regex(portRgxStr, RegexOptions.Compiled);
        codecRgx = new Regex(codecRgxStr, RegexOptions.Compiled);
        SDPIPRgx = new Regex(SDPIPRgxStr, RegexOptions.Compiled);
        mAudioRgx = new Regex(mAudioRgxStr, RegexOptions.Compiled);
        occasRgx = new Regex(occasRgxStr, RegexOptions.Compiled);
        cseqRgx = new Regex(cseqRgxStr, RegexOptions.Compiled);
        statusBarTxtClr = AttrColor.White;
        statusBarBkgrdClr = AttrColor.Black;
        headerTxtClr = AttrColor.Green;
        headerBkgrdClr = AttrColor.DarkBlue;
        fieldConsoleTxtClr = ConsoleColor.Gray;
        fieldConsoleBkgrdClr = ConsoleColor.DarkBlue;
        fieldConsoleSelectClr = ConsoleColor.Yellow;
        fieldConsoleTxtInvrtClr = ConsoleColor.DarkBlue;
        fieldConsoleBkgrdInvrtClr = ConsoleColor.Gray;
        msgBoxTxt = ConsoleColor.White;
        msgBoxBkgrd = ConsoleColor.DarkGray;
        fieldAttrTxtClr = AttrColor.Gray;
        fieldAttrTxtInvrtClr = AttrColor.DarkBlue;
        fieldAttrBkgrdClr = AttrColor.DarkBlue;
        fieldAttrBkgrdInvrtClr = AttrColor.Gray;
        fieldAttrSelectClr = AttrColor.Yellow;
        footerTxtClr = AttrColor.Cyan;
        footerBkgrdClr = AttrColor.DarkBlue;
        sortTxtdClr = AttrColor.DarkBlue;
        sortBkgrdClr = AttrColor.Green;
        fakeCursor[0] = 0;
        fakeCursor[1] = 0;
        IncludePorts = false;
        showNotify = false;
        methodDisplayed = "invite";
        dupIP = false;
        IPprevNumSelectMsg = 0;
        numSelectedCalls = 0;
        sortFields = new string[5, 3]
        {
            { "time", "21", "0"} ,
            { "from:", "34", "3"} ,
            { "to:", "65", "2"} ,
            { "src IP", "96", "6"} ,
            { "dst IP", "113", "7"}
        };
        callsDisplaysortIdx = 0;
        filter = new String[20];
        writeFlowToFile = false;
        htmlFlowToFile = false;
    }

    static void Main(String[] arg)
    {
        try
        {
            string[] fileAry = new string[100];
            float version = 2f;
            string dotNetVersion = Environment.Version.ToString();
            SiplogTWO SiplogTWOObj = new SiplogTWO();
            if (Console.BufferWidth < 200) { Console.BufferWidth = 200; }
            Console.Clear();
            Console.SetCursorPosition(0, 0); Console.WriteLine();
            Console.WriteLine(@"     _____ _____ ____  _            ");
            Console.WriteLine(@"    / ____|_   _| __ \| |           ");
            Console.WriteLine(@"   | (___   | | | __) | | ___   __ _");
            Console.WriteLine(@"    \___ \  | | | ___/| |/ _ \ / _` |");
            Console.WriteLine(@"    ____) |_| |_| |   | | (_) | (_| |");
            Console.WriteLine(@"   |_____/|_____|_|   |_|\___/ \__, |");
            Console.WriteLine(@"                                __/ |");
            Console.WriteLine(@"                               |___/ ");
            Console.WriteLine("   Version {0}              Greg Palmer", version.ToString());
            if (!Regex.IsMatch(dotNetVersion, @"^4\."))
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(@"SIPlog requires .NET 4 runtime https://www.microsoft.com/net/download/windows");
                Console.ForegroundColor = ConsoleColor.Gray;
                Environment.Exit(1);
            }
            for (int i = 0; i < arg.Length; i++)  //check for options
            {
                if (arg[i] == "-p") { SiplogTWOObj.IncludePorts = true; }
                if (arg[i] == "-v")
                {
                    Console.WriteLine("Version " + version.ToString());
                    Environment.Exit(0);
                }
                if (arg[i] == "-d")
                {
                    if (!string.IsNullOrEmpty(arg[i + 1]))
                    {
                        fileAry = Directory.GetFiles(arg[i + 1]);
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Missing directory parameter");
                        Environment.Exit(1);
                    }
                }
                else
                {
                    fileAry = arg;
                }
            }
            SiplogTWOObj.displayMode = "calls";
            Array.Sort(fileAry);
            Thread FileReadThread = new Thread(() => { SiplogTWOObj.FileReader(fileAry); });
            FileReadThread.Name = "File Reader Thread";
            FileReadThread.Start();
            SiplogTWOObj.CallSelect();
        }
        catch (Exception ex)
        {
            lock (_locker)
            {
                Console.WriteLine("\nMessage ---\n{0}", ex.Message);
                Console.WriteLine(
                    "\nHelpLink ---\n{0}", ex.HelpLink);
                Console.WriteLine("\nSource ---\n{0}", ex.Source);
                Console.WriteLine(
                    "\nStackTrace ---\n{0}", ex.StackTrace);
                Console.WriteLine(
                    "\nTargetSite ---\n{0}", ex.TargetSite);
                Console.ReadKey(true);
            }
        }
    }

    void TopLine(string line, short x)
    {
        string displayLine;
        if (line.Length > 1)
        {
            displayLine = line + new String(' ', Math.Max(Console.BufferWidth - line.Length, 0));
        }
        else
        {
            displayLine = line;
        }
        ConsoleBuffer.SetAttribute(x, 0, line.Length, (short)(statusBarTxtClr + (short)(((short)statusBarBkgrdClr) * 16)));
        ConsoleBuffer.WriteAt(x, 0, displayLine);
    }

    void WriteScreen(string line, short x, short y, AttrColor attr, AttrColor bkgrd)
    {
        ConsoleBuffer.SetAttribute(x, y, line.Length, (short)(attr + (short)(((short)bkgrd) * 16)));
        ConsoleBuffer.WriteAt(x, y, line);
    }

    void WriteConsole(string line, AttrColor attr, AttrColor bkgrd)
    {
        if (writeFlowToFile)
        {
            if (htmlFlowToFile)
            {
                string htmlTxtClr;
                if (attr.ToString() == "Cyan")
                {
                    htmlTxtClr = "DarkTurquoise";
                }
                else if (attr.ToString() == "Yellow")
                {
                    htmlTxtClr = "GoldenRod";
                }
                else if (attr.ToString() == "DarkGreen")
                {
                    htmlTxtClr = "YellowGreen";
                }
                else if (attr.ToString() == "DarkCyan")
                {
                    htmlTxtClr = "CadetBlue";
                }
                else if (attr.ToString() == "Gray")
                {
                    htmlTxtClr = "Black";
                }
                else
                {
                    htmlTxtClr = attr.ToString();
                }
                flowFileWriter.Write("<code style = \"color:" + htmlTxtClr + ";\" >");
                
            }
            flowFileWriter.Write(line);
            if (htmlFlowToFile) { flowFileWriter.Write("</code>"); }
        }
        else
        {
            WriteScreen(line, (short)fakeCursor[0], (short)fakeCursor[1], attr, bkgrd);
            fakeCursor[0] = fakeCursor[0] + line.Length;
        }
    }

    void WriteLineConsole(string line, AttrColor attr, AttrColor bkgrd)
    {
        if (writeFlowToFile)
        {
            flowFileWriter.WriteLine(line);
        }
        else
        {
            WriteConsole(line + new String(' ', Console.BufferWidth - line.Length)
            , attr, bkgrd);
            fakeCursor[1]++;
            fakeCursor[0] = 0;
        }
    }

    void ClearConsole()
    {
        bool iswriteFlowToFileTrue = writeFlowToFile;
        writeFlowToFile = false;
        int[] prevFakeCursor = new int[2];
        prevFakeCursor = fakeCursor;
        fakeCursor[0] = 0; fakeCursor[1] = 0;
        for (int i = 0; i < Console.BufferHeight; i++)
        {
            WriteLineConsole("", fieldAttrTxtClr, fieldAttrBkgrdClr);
        }
        fakeCursor = prevFakeCursor;
        writeFlowToFile = iswriteFlowToFileTrue;
    }

    void ClearConsoleNoTop()
    {
        bool iswriteFlowToFileTrue = writeFlowToFile;
        writeFlowToFile = false;
        int[] prevFakeCursor = new int[2];
        prevFakeCursor = fakeCursor;
        fakeCursor[0] = 0; fakeCursor[1] = 1;
        for (int i = 0; i < Console.BufferHeight; i++)
        {
            WriteLineConsole("", fieldAttrTxtClr, fieldAttrBkgrdClr);
        }
        fakeCursor = prevFakeCursor;
        writeFlowToFile = iswriteFlowToFileTrue;
    }

    void FileReader(string[] filenames)
    {
        int fileNum = 0;
        if (filenames.Length == 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("\nNO FILES WERE SPECIFIED - Usage: siplog.exe logfile.log anotherlogfile.log ... ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Environment.Exit(1);
        }
        foreach (String file in filenames)
        {
            if (!File.Exists(file) && !Regex.IsMatch(file, @"^-\w\b"))
            {
                Console.WriteLine("\nFile " + file + " does not exist ");
                Environment.Exit(1);
            }
        }
        foreach (string file in filenames)
        {
            fileNum++;
            if (!Regex.IsMatch(file, @"^-\w\b"))
            {
                currentFileLoadLeng = 0;
                currentFileLoadProg = 0;
                short x = 0;
                //count the number of lines in a file
                using (StreamReader sr = new StreamReader(file))
                {
                    string line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        currentFileLoadLeng++;
                        if (currentFileLoadLeng % 20000 == 0)
                        {
                            x = (short)(currentFileLoadLeng / 20000);
                            TopLine(".", (short)(x - 1));
                        }
                    }
                    sr.Close();
                    TopLine(" Reading " + currentFileLoadLeng + " lines of File " + fileNum + "/" + filenames.Length + " : " + file, (short)(x));
                }
                using (fileSread = new StreamReader(file))
                {
                    while (!fileSread.EndOfStream)
                    {
                        ReadData(file);
                    }
                   
                }
                fileSread.Close();
                
                lock (_locker)
                {
                    messages = messages.OrderBy(theDate => theDate[1]).ThenBy(Time => Time[2]).ToList();
                }

            }
        }
        lock (_locker)
        {
            TopLine("Done reading all files " + string.Join(" ", filenames), 0);
            SortCalls();
            if (displayMode == "calls") CallDisplay(true);
            Console.SetWindowPosition(0, 0);
            Console.SetCursorPosition(0, 4);
            fileReadDone = true;
        }
    }

    string GetNextLine()
    {
        string line;
        line = fileSread.ReadLine();
        UpdateFileLoadProgress();
        return line;
    }

    void ReadData(string fileName)
    {
        string line = GetNextLine();
        if (line != null)
        {
            while (!string.IsNullOrEmpty(line) && beginmsgRgx.IsMatch(line))
            {
                String[] outputarray = new String[18];
                // get the index of the start of the msg
                outputarray[0] = currentFileLoadProg.ToString();
                outputarray[1] = dateRgx.Match(line).ToString();    //date  
                outputarray[2] = timeRgx.Match(line).ToString();     //time
                if (IncludePorts) { outputarray[3] = srcIpPortRgx.Match(line).ToString(); }
                else { outputarray[3] = srcIpRgx.Match(line).ToString(); }                               //src IP                                                                        
                if (IncludePorts) { outputarray[4] = dstIpPortRgx.Match(line).ToString(); }
                else { outputarray[4] = dstIpRgx.Match(line).ToString(); }
                line = GetNextLine();
                if (line == null) { break; }
                //check to match these only once. no need match a field if it is already found
                bool sipTwoDotOfound = false;
                Match sipTwoDotO;
                Match callid;
                Match cseq;
                Match to;
                Match from;;
                Match SDPIP;
                Match ua;
                Match serv;
                while (!beginmsgRgx.IsMatch(line)) //untill the begining of the next msg
                {
                    switch (line)
                    {
                        case string s when (sipTwoDotO = requestRgx.Match(s)) != Match.Empty:
                            outputarray[5] = sipTwoDotO.ToString();
                            sipTwoDotOfound = true;
                            break;
                        case string s when (callid = callidRgx.Match(s)) != Match.Empty:
                            outputarray[6] = callid.ToString().Trim();
                            break;
                        case string s when (cseq = cseqRgx.Match(s)) != Match.Empty:
                            outputarray[17] = cseq.Groups[2].ToString();
                            break;
                        case string s when (to = toRgx.Match(s)) != Match.Empty:
                            outputarray[7] = to.Groups[1].ToString() + to.Groups[3].ToString();
                            break;
                        case string s when (from = fromRgx.Match(s)) != Match.Empty:
                            outputarray[8] = from.Groups[1].ToString() + from.Groups[3].ToString();
                            break;
                        case string s when s.Contains("Content-Type: application/sdp"):
                            outputarray[11] = " SDP";
                            break;
                        case string s when (SDPIP = SDPIPRgx.Match(s)) != Match.Empty:
                            outputarray[13] = SDPIP.ToString();
                            break;
                        case string s when mAudioRgx.IsMatch(s):
                            outputarray[14] = portRgx.Match(s).ToString().Trim();
                            outputarray[15] = codecRgx.Match(s).ToString().Trim();
                            if (outputarray[15] == "0") { outputarray[15] = "G711u"; }
                            else if (outputarray[15] == "8") { outputarray[15] = "G711a"; }
                            else if (outputarray[15] == "9") { outputarray[15] = "G722"; }
                            else if (outputarray[15] == "18") { outputarray[15] = "G729"; }
                            else { outputarray[15] = "rtp-payload type:" + outputarray[15]; }
                            break;
                        case string s when (ua = uaRgx.Match(s)) != Match.Empty:
                            outputarray[16] = ua.ToString().Trim();
                            break;
                        case string s when (serv = serverRgx.Match(s)) != Match.Empty:
                            outputarray[16] = serv.ToString().Trim();
                            break;
                        case string s when occasRgx.IsMatch(s):
                            outputarray[16] = "occas";
                            break;

                    }
                    line = GetNextLine();
                    if (line == null) { break; }
                }
                // get the index of the end of the msg
                outputarray[9] = currentFileLoadProg.ToString();
                outputarray[10] = "Gray";
                outputarray[12] = fileName; //add file name 
                if (outputarray[5] == null) { outputarray[5] = "Invalid SIP characters"; }
                if (sipTwoDotOfound)
                {
                    lock (_locker)
                    {
                        messages.Add(outputarray);
                    }
                    if (displayMode == "flow")
                    {
                        if (callIDsOfIntrest.Contains(outputarray[6]))
                        {
                            Flow(true);
                        }
                    }
                    bool getcallid = false;
                    if (outputarray[3] != outputarray[4])
                    {
                        if (outputarray[5].Contains("INVITE") || outputarray[5].Contains("NOTIFY") || outputarray[5].Contains("REGISTER") || outputarray[5].Contains("SUBSCRIBE"))
                        {
                            if (callLegs.Count > 0) // if it is not the first message
                            {
                                //check if call-id was not already gotten
                                for (int j = 0; j < callLegs.Count; j++)
                                {
                                    getcallid = true;

                                    if (callLegs[j][4] == outputarray[6]) // check if re-invite
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
                                arrayout[0] = outputarray[1];//  date [0]
                                arrayout[1] = outputarray[2];//  time [1]
                                arrayout[2] = outputarray[7];//  To: [2]
                                arrayout[3] = outputarray[8];//  From: [3]
                                arrayout[4] = outputarray[6];//  Call-ID [4]
                                arrayout[5] = " ";                //  selected [5]  " " = not selected
                                arrayout[6] = outputarray[3];//  src IP [6]
                                arrayout[7] = outputarray[4];//  dst ip [7]
                                arrayout[8] = "filtered";
                                if (outputarray[5].Contains("INVITE")) { arrayout[9] = "invite"; CallInvites++; }
                                else if (outputarray[5].Contains("NOTIFY")) { arrayout[9] = "notify"; notifications++; }
                                else if (outputarray[5].Contains("REGISTER")) { arrayout[9] = "register"; registrations++; }
                                else if (outputarray[5].Contains("SUBSCRIBE")) { arrayout[9] = "subscribe"; subscriptions++; }
                                if (outputarray[6] != null)
                                {
                                    lock (_locker)
                                    {
                                        callLegs.Add(arrayout);
                                        if (displayMode == "calls")
                                        {
                                            if (arrayout[9] == methodDisplayed || (showNotify && arrayout[9] == "notify"))
                                            {
                                                CallFilter();
                                                CallDisplay(false);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            UpdateFileLoadProgress(); 
        }
    }

    void UpdateFileLoadProgress()
    {
        currentFileLoadProg++;
        if (currentFileLoadProg % 20000 == 0)
        {
            short x;
            x = (short)(currentFileLoadProg / 20000);
            lock (_locker) { TopLine("!", (short)(x - 1)); }
        }
    }

    void CallDisplay(bool newFullScreen)
    {
        Console.WindowWidth = Math.Min(161, Console.LargestWindowWidth);
        Console.WindowHeight = Math.Min(44, Console.LargestWindowHeight);
        Console.BufferWidth = 200;
        Console.BufferHeight = Math.Max(10 + callLegsDisplayed.Count, Console.BufferHeight);
        //if the following conditions true , just add the calls to the bottom of the screen without redrawing
        if (!newFullScreen && !filterChange && callLegsDisplayedCountPrev != 0 && callLegsDisplayed.Count > callLegsDisplayedCountPrev)
        {
            for (int i = callLegsDisplayedCountPrev; i < callLegsDisplayed.Count; i++)
            {
                WriteScreenCallLine(callLegsDisplayed[i], i);
            }
        }
        else
        {
            filterChange = false;
            callLegsDisplayedCountPrev = callLegsDisplayed.Count;
            ClearConsoleNoTop();
            fakeCursor[0] = 0; fakeCursor[1] = 1;
            WriteConsole("[Spacebar]-select calls [Enter]-for call flow [F]-filter [Q]-query all SIP msgs [Esc]-quit [N]-toggle NOTIFYs [O]-OPTIONs ", headerTxtClr, headerBkgrdClr);
            if (methodDisplayed == "invite") { WriteConsole("[R]-registrations [S]-subscriptions", headerTxtClr, headerBkgrdClr); }
            if (methodDisplayed == "register") { WriteConsole("[I]-invites/calls [S]-subscriptions", headerTxtClr, headerBkgrdClr); }
            if (methodDisplayed == "subscribe") { WriteConsole("[I]-invites/calls [R]-registrations", headerTxtClr, headerBkgrdClr); }
            WriteLineConsole(" ", headerTxtClr, headerBkgrdClr); 
            String formatedStr = String.Format("{0,-2} {1,-6} {2,-10} {3,-12} {4,-30} {5,-30} {6,-16} {7,-16}", "*", "index", "date", "time", "from:", "to:", "src IP", "dst IP");
            WriteLineConsole(formatedStr, headerTxtClr, headerBkgrdClr);
            if (methodDisplayed == "invite") { WriteConsole("----invites/calls---", headerTxtClr, headerBkgrdClr); }
            if (methodDisplayed == "register") { WriteConsole("----registrations---", headerTxtClr, headerBkgrdClr); }
            if (methodDisplayed == "subscribe") { WriteConsole("----subscriptions---", headerTxtClr, headerBkgrdClr); }
            WriteLineConsole(new String('-', 140), headerTxtClr, headerBkgrdClr);
            if (callLegsDisplayed.Count > 0)
            {
                for (int i = 0; i < callLegsDisplayed.Count; i++)
                {
                    WriteScreenCallLine(callLegsDisplayed[i], i);
                }
            }
            WriteScreen(sortFields[callsDisplaysortIdx, 0], Int16.Parse(sortFields[callsDisplaysortIdx, 1]), 2, sortTxtdClr, sortBkgrdClr);
        }
        string footerOne = "Number of SIP messages found : " + messages.Count.ToString();
        string footerTwo = "Number of SIP transactions found : " + callLegs.Count.ToString();
        string footerThree = CallInvites.ToString() + " SIP INVITEs found | " + notifications.ToString() + " SIP NOTIFYs found | " + registrations.ToString() + " SIP REGISTERs found | " + subscriptions.ToString() + " SIP SUBSCRIBEs found";
        WriteScreen(footerOne + new String(' ', Console.BufferWidth - footerOne.Length), 0, (short)(callLegsDisplayed.Count + 4), footerTxtClr, footerBkgrdClr);
        WriteScreen(footerTwo + new String(' ', Console.BufferWidth - footerTwo.Length), 0, (short)(callLegsDisplayed.Count + 5), footerTxtClr, footerBkgrdClr);
        WriteScreen(footerThree + new String(' ', Console.BufferWidth - footerThree.Length), 0, (short)(callLegsDisplayed.Count + 6), footerTxtClr, footerBkgrdClr);
        if (callLegsDisplayed.Count > 0)
        {
            Console.SetCursorPosition(0, CallListPosition + 4);
            Console.BackgroundColor = fieldConsoleTxtClr;
            Console.ForegroundColor = fieldConsoleBkgrdClr;
            CallLine(callLegsDisplayed[CallListPosition], CallListPosition);
            Console.SetCursorPosition(0, CallListPosition + 4);
            Console.BackgroundColor = fieldConsoleBkgrdClr;
            Console.ForegroundColor = fieldConsoleTxtClr;
        }
    }

    void CallLine(string[] InputCallLegs, int indx)
    {
        if (InputCallLegs.Length == 10)
        {
            if (InputCallLegs[5] == "*")
            {
                Console.ForegroundColor = fieldConsoleSelectClr;
            }
            Console.WriteLine("{0,-2} {1,-6} {2,-10} {3,-12} {5,-30} {4,-30} {6,-16} {7,-17}"
                , InputCallLegs[5]
                , indx
                , InputCallLegs[0]
                , ((InputCallLegs[1]).Substring(0, 11)) ?? String.Empty
                , InputCallLegs[2]
                , InputCallLegs[3]
                , InputCallLegs[6]
                , InputCallLegs[7]);
            Console.ForegroundColor = fieldConsoleTxtClr;
        }
    }

    void WriteScreenCallLine(string[] callLeg, int indx)
    {
        if (callLeg.Length == 10)
        {
            AttrColor txtColor;
            AttrColor bkgrdColor;
            short y = (short)(indx + 4);
            if (callLeg[5] == "*")
            {
                txtColor = fieldAttrSelectClr;
                if (indx == CallListPosition)
                {
                    bkgrdColor = fieldAttrBkgrdInvrtClr;
                }
                else
                {
                    bkgrdColor = fieldAttrBkgrdClr;
                }
            }
            else
            {
                txtColor = fieldAttrTxtClr;
                if (indx == CallListPosition)
                {
                    txtColor = fieldAttrTxtInvrtClr;
                    bkgrdColor = fieldAttrBkgrdInvrtClr;
                }
                else
                {
                    txtColor = fieldAttrTxtClr;
                    bkgrdColor = fieldAttrBkgrdClr;
                }
            }
            string formatedStr = String.Format("{0,-2} {1,-6} {2,-10} {3,-12} {5,-30} {4,-30} {6,-16} {7,-17}"
                , callLeg[5]
                , indx
                , callLeg[0]
                , callLeg[1].Substring(0, 11)
                , callLeg[2]
                , callLeg[3]
                , callLeg[6]
                , callLeg[7]);
            WriteScreen(formatedStr, 0, y, txtColor, bkgrdColor);
        }
    }

    void CallFilter()
    {
        lock (_locker)
        {
            callLegsDisplayed.Clear();
            if (!string.IsNullOrEmpty(filter[0]))
            {
                for (int i = 0; i < callLegs.Count; i++)
                {
                    bool addcall = false;
                    for (int j=0;j< callLegs[i].Length;j++) 
                    {
                        String callitem = callLegs[i][j];
                        if (!String.IsNullOrEmpty(callitem))
                        {
                            foreach (String filteritem in filter)
                            {
                                if (callitem.Contains(filteritem))
                                {
                                    if ((showNotify && callLegs[i][9] == "notify") || (callLegs[i][9] == methodDisplayed)) { addcall = true; }                                     
                                }
                            }
                        }
                    }
                    if (addcall) { callLegsDisplayed.Add(callLegs[i]); }
                }
            }
            else
            {
                for (int i = 0; i < callLegs.Count; i++)
                {
                    bool addcall = false;
                    foreach (String callitem in callLegs[i])
                    {
                        foreach (String filteritem in filter)
                        {
                            if ((showNotify && callLegs[i][9] == "notify") || (callLegs[i][9] == methodDisplayed)) { addcall = true; }
                        }
                    }
                    if (addcall) { callLegsDisplayed.Add(callLegs[i]); }
                }
            }
        }
    }

    void MoveCursor(bool up, int amount)
    {
        lock (_locker)
        {
            Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
            Console.ForegroundColor = fieldConsoleTxtClr;
            CallLine(callLegsDisplayed[CallListPosition], CallListPosition);
            if (up)
            {
                CallListPosition -= amount;
                Console.CursorTop -= (amount + 1);
            }
            else
            {
                CallListPosition += amount;
                Console.CursorTop += (amount - 1);
            }
            Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
            Console.ForegroundColor = fieldConsoleTxtInvrtClr;
            CallLine(callLegsDisplayed[CallListPosition], CallListPosition);
            Console.CursorTop -= 1;
            Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
            Console.ForegroundColor = fieldConsoleTxtClr;
        }
    }

    void CallSelect()
    {
        bool done = false;
        CallListPosition = 0;

        lock (_locker)
        {
            while (!(displayMode == "calls"))
            {
                Monitor.Wait(_locker);
            }
            CallDisplay(true);
            Console.SetCursorPosition(0, 4);
            Console.SetWindowPosition(0, 0);
        }
        ConsoleKeyInfo keypressed;
        while (done == false)
        {
            keypressed = Console.ReadKey(true);
            if (keypressed.Key == ConsoleKey.DownArrow)
            {
                if (CallListPosition < callLegsDisplayed.Count - 1)
                {
                    MoveCursor(false, 1);
                }
            }
            if (keypressed.Key == ConsoleKey.PageDown)
            {
                if (CallListPosition + 40 < callLegsDisplayed.Count - 1)
                {
                    MoveCursor(false, 40);
                }
                else
                {
                    MoveCursor(false, (callLegsDisplayed.Count - 1) - CallListPosition);
                }
            }
            if (keypressed.Key == ConsoleKey.UpArrow)
            {
                if (CallListPosition > 0)
                {
                    MoveCursor(true, 1);
                }
                else
                {
                    Console.SetWindowPosition(0, 0);
                }
            }
            if (keypressed.Key == ConsoleKey.PageUp)
            {
                if (CallListPosition > 40)
                {
                    MoveCursor(true, 40);
                }
                else
                {
                    MoveCursor(true, CallListPosition);
                }
                if (CallListPosition == 0)
                {
                    Console.SetWindowPosition(0, 0);
                }
            }
            if (callLegsDisplayed.Count > 0 && keypressed.Key == ConsoleKey.Spacebar)
            {
                if (callLegsDisplayed[CallListPosition][5] == "*")
                {
                    int clindx = callLegs.FindIndex(
                        delegate (string[] cl)
                        {
                            if (cl == callLegsDisplayed[CallListPosition])
                            {
                                return true;
                            }
                            else
                            {
                                return false;
                            }
                        }
                    );
                    callLegsDisplayed[CallListPosition][5] = " ";
                    callLegs[clindx][5] = " ";
                    numSelectedCalls--;
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                    CallLine(callLegsDisplayed[CallListPosition], CallListPosition);
                    Console.CursorTop = Console.CursorTop - 1;
                }
                else
                {
                    int clindx = callLegs.FindIndex(
                        delegate (string[] cl)
                        {
                            if (cl == callLegsDisplayed[CallListPosition])
                            {
                                return true;
                            }
                            else
                            {
                                return false;
                            }
                        }
                    );
                    callLegsDisplayed[CallListPosition][5] = "*";
                    callLegs[clindx][5] = "*";
                    numSelectedCalls++;
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;   //change the colors of the current postion to inverted
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                    CallLine(callLegsDisplayed[CallListPosition], CallListPosition);
                    Console.CursorTop = Console.CursorTop - 1;
                }
                callIDsOfIntrest.Clear();
                for (int i = 0; i < callLegs.Count; i++)       //find the selected calls from the call Legs Displayed
                {
                    if (callLegs[i][5] == "*")
                    {
                        callIDsOfIntrest.Add(callLegs[i][4]);           //get the callIDs from the selected calls and add them to callIDsOfIntrest
                    }
                }
            }
            if (numSelectedCalls > 0 && keypressed.Key == ConsoleKey.Enter)
            {
                displayMode = "flow";
                FlowSelect();   //select SIP message from the call flow diagram                        
                filterChange = true;
                CallFilter();
                displayMode = "calls";
                if (fileReadDone)
                {
                    SortCalls();
                }
                Console.SetWindowPosition(0, Math.Max(0, Console.CursorTop - Console.WindowHeight));
                CallDisplay(true);
            }
            if (keypressed.Key == ConsoleKey.Escape)
            {
                lock (_locker)
                {
                    Console.ForegroundColor = msgBoxTxt;
                    Console.BackgroundColor = msgBoxBkgrd;
                    int center = Math.Max(0, (int)Math.Floor((decimal)((Console.WindowWidth - 42) / 2)));
                    Console.CursorLeft = center; Console.WriteLine(@"+--------------------------------------+\ ");
                    Console.CursorLeft = center; Console.WriteLine(@"|  Are you sure you want to quit? Y/N? | |");
                    Console.CursorLeft = center; Console.WriteLine(@"+--------------------------------------+ |");
                    Console.CursorLeft = center; Console.WriteLine(@" \______________________________________\|");
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    bool tryAgain = true;
                    while (tryAgain)
                        switch (Console.ReadKey(true).Key)
                        {
                            case ConsoleKey.Y:
                                Console.Clear();
                                System.Environment.Exit(0);
                                break;
                            case ConsoleKey.N:
                                tryAgain = false;
                                filterChange = true;
                                CallFilter();
                                if (fileReadDone) { SortCalls(); }
                                Console.SetWindowPosition(0, Math.Max(0, Console.CursorTop - Console.WindowHeight));
                                CallDisplay(true);
                                break;
                        }
                }
            }
            if (keypressed.Key == ConsoleKey.Q)
            {
                do
                {
                    displayMode = "messages";
                    ListAllMsg(null);
                    Console.ForegroundColor = msgBoxTxt;
                    Console.BackgroundColor = msgBoxBkgrd;
                    int center = Math.Max(0, (int)Math.Floor((decimal)((Console.WindowWidth - 71) / 2)));
                    Console.CursorLeft = center; Console.WriteLine(@"+-------------------------------------------------------------------+\ ");
                    Console.CursorLeft = center; Console.WriteLine(@"|  Press any key to query SIP messages again or press [esc] to quit | |");
                    Console.CursorLeft = center; Console.WriteLine(@"+-------------------------------------------------------------------+ |");
                    Console.CursorLeft = center; Console.WriteLine(@" \___________________________________________________________________\|");
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                } while (Console.ReadKey(true).Key != ConsoleKey.Escape);
                filterChange = true;
                CallFilter();
                if (fileReadDone) { SortCalls(); }
                Console.SetWindowPosition(0, Math.Max(0, Console.CursorTop - Console.WindowHeight));
                CallDisplay(true);
                displayMode = "calls";
            }
            if (keypressed.Key == ConsoleKey.F)
            {
                lock (_locker)
                {
                    filterChange = true;
                    Console.ForegroundColor = msgBoxTxt;
                    Console.BackgroundColor = msgBoxBkgrd;
                    int center = Math.Max(0, (int)Math.Floor((decimal)((Console.WindowWidth - 136) / 2)));
                    Console.CursorLeft = center; Console.WriteLine(@"+------------------------------------------------------------------------------------------------------------------------------------+\ ");
                    Console.CursorLeft = center; Console.WriteLine(@"| Enter space separated items like extensions, names or IP. Items are OR. Case sensitive. Leave blank for no Filter.                 | |");
                    Console.CursorLeft = center; Console.WriteLine(@"|                                                                                                                                    | |");
                    Console.CursorLeft = center; Console.WriteLine(@"+------------------------------------------------------------------------------------------------------------------------------------+ |");
                    Console.CursorLeft = center; Console.WriteLine(@" \____________________________________________________________________________________________________________________________________\|");
                    Console.CursorTop -= 3;
                    Console.CursorLeft = center + 2;
                    filter = Console.ReadLine().Split(' ');
                    CallFilter();
                    if (fileReadDone) { SortCalls(); }
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    CallListPosition = 0;
                    CallDisplay(true);
                    Console.SetWindowPosition(0, 0);
                    Console.SetCursorPosition(0, 4);
                }
            }
            if (keypressed.Key == ConsoleKey.N)
            {
                CallListPosition = 0;
                if (showNotify == false) { showNotify = true; } else { showNotify = false; }
                filterChange = true;
                CallFilter();
                if (fileReadDone) { SortCalls(); }
                Console.SetWindowPosition(0, Math.Max(0, Console.CursorTop - Console.WindowHeight));
                CallDisplay(true);
            }
            
            if (keypressed.Key == ConsoleKey.O)
            {
                lock (_locker)
                {
                    Console.ForegroundColor = msgBoxTxt;
                    Console.BackgroundColor = msgBoxBkgrd;
                    int center = Math.Max(0, (int)Math.Floor((decimal)((Console.WindowWidth - 136) / 2)));
                    Console.CursorLeft = center; Console.WriteLine(@"+-------------------------------------------------------------------------+\ ");
                    Console.CursorLeft = center; Console.WriteLine(@"| Enter the IP address of the device to view if it is answering OPTIONS : | |");
                    Console.CursorLeft = center; Console.WriteLine(@"|                                                                         | |");
                    Console.CursorLeft = center; Console.WriteLine(@"+-------------------------------------------------------------------------+ |");
                    Console.CursorLeft = center; Console.WriteLine(@" \_________________________________________________________________________\|");
                    Console.CursorTop -= 3;
                    Console.CursorLeft = center + 2;
                    string IPaddr = Console.ReadLine();
                    if (String.IsNullOrEmpty(IPaddr))
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.CursorTop = Console.CursorTop - 1;
                        Console.CursorLeft = center;
                        Console.WriteLine("| No IP address was entered. Press any key to continue");
                        Console.ForegroundColor = fieldConsoleTxtClr;
                        Console.CursorVisible = true;
                        Console.ReadKey(true);
                        Console.CursorTop -= 4;
                    }
                    else
                    {
                        displayMode = "messages";
                        ListAllMsg(IPaddr + ".*OPTIONS|" + IPaddr + ".*200 OK.*OPTIONS");
                    }
                    Console.BackgroundColor = fieldConsoleBkgrdClr;  //change the colors of the current postion to normal
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    filterChange = true;
                    CallFilter();
                    if (fileReadDone) { SortCalls(); }
                    Console.SetWindowPosition(0, Math.Max(0, Console.CursorTop - Console.WindowHeight));
                    CallDisplay(true);
                }
            }
            if (methodDisplayed != "register" && keypressed.Key == ConsoleKey.R)
            {
                string prevMethod = methodDisplayed;
                filterChange = true;
                methodDisplayed = "register";
                ClearSelectedCalls();
                numSelectedCalls = 0;
                CallListPosition = 0;
                CallFilter();
                if (fileReadDone) { SortCalls(); }
                CallDisplay(true);
                Console.SetWindowPosition(0, 0);
                Console.SetCursorPosition(0, 4);
            }
            if (methodDisplayed != "subscribe" && keypressed.Key == ConsoleKey.S)
            {
                string prevMethod = methodDisplayed;
                filterChange = true;
                ClearSelectedCalls();
                numSelectedCalls = 0;
                methodDisplayed = "subscribe";
                CallListPosition = 0;
                CallFilter();
                if (fileReadDone) { SortCalls(); }
                CallDisplay(true);
                Console.SetWindowPosition(0, 0);
                Console.SetCursorPosition(0, 4);
            }
            if (methodDisplayed != "invite" && keypressed.Key == ConsoleKey.I)
            {
                string prevMethod = methodDisplayed;
                filterChange = true;
                methodDisplayed = "invite";
                numSelectedCalls = 0;
                ClearSelectedCalls();
                CallListPosition = 0;
                CallFilter();
                if (fileReadDone) { SortCalls(); }
                CallDisplay(true);
                Console.SetWindowPosition(0, 0);
                Console.SetCursorPosition(0, 4);
            }
            if (fileReadDone && keypressed.Key == ConsoleKey.LeftArrow)
            {
                if (callsDisplaysortIdx > 0)
                {
                    WriteScreen(sortFields[callsDisplaysortIdx, 0], Int16.Parse(sortFields[callsDisplaysortIdx, 1]), 2, headerTxtClr, headerBkgrdClr);
                    callsDisplaysortIdx--;
                    CallFilter();
                    SortCalls();
                    CallDisplay(true);
                    Console.SetWindowPosition(0, 0);
                    Console.SetCursorPosition(0, 4);
                }
            }
            if (fileReadDone && keypressed.Key == ConsoleKey.RightArrow)
            {
                if (callsDisplaysortIdx < 4)
                {
                    WriteScreen(sortFields[callsDisplaysortIdx, 0], Int16.Parse(sortFields[callsDisplaysortIdx, 1]), 2, headerTxtClr, headerBkgrdClr);
                    callsDisplaysortIdx++;
                    CallFilter();
                    SortCalls();
                    CallDisplay(true);
                    Console.SetWindowPosition(0, 0);
                    Console.SetCursorPosition(0, 4);
                }
            }
        }
    }

    void SortCalls()
    {
        if (callsDisplaysortIdx == 0)
        {
            callLegsDisplayed = callLegsDisplayed.OrderBy(theDate => theDate[0]).ThenBy(Time => Time[1]).ToList();
            CallListPosition = 0;
        }
        else
        {
            callLegsDisplayed = callLegsDisplayed.OrderBy(field => field[Int16.Parse(sortFields[callsDisplaysortIdx, 2])]).ToList();
            CallListPosition = 0;
        }
    }

    void ClearSelectedCalls()
    {
        for (int i = 0; i < callLegsDisplayed.Count; i++)
        {
            callLegsDisplayed[i][5] = " ";
        }
    }

    void SelectMessages()
    {
        lock (_locker)
        {
            selectedmessages.Clear();
            for (int i = 0; i < messages.Count; i++)                //find messages that contain the selected callid
            {
                if (callIDsOfIntrest.Contains(messages[i][6]))
                {
                    if (messages[i][3] != messages[i][4])
                    {
                        selectedmessages.Add(messages[i]);
                    }
                    else if (dupIP)
                    {
                        selectedmessages.Add(messages[i]);
                    }
                }
            }
            CallLegColors callcolor = CallLegColors.Green;
            foreach (string cid in callIDsOfIntrest)                         //get all the messages with the callIDs fro tmhe selected call Legs
            {
                for (int i = 0; i < selectedmessages.Count; i++)
                {
                    if (cid == selectedmessages[i][6])
                    {
                        selectedmessages[i][10] = callcolor.ToString();     //set color to display the call leg in the flow color for each call id
                    }
                }
                if (callcolor == CallLegColors.DarkMagenta) { callcolor = CallLegColors.Green; } else { callcolor++; }
            }
        }
    }

    void GetIps()
    {
        if (IPprevNumSelectMsg != selectedmessages.Count)
        {
            IPsOfIntrest.Clear();
            IPprevNumSelectMsg = selectedmessages.Count;
            for (int i = 0; i < selectedmessages.Count; i++)
            {
                if (!IPsOfIntrest.Contains(selectedmessages[i][3]))
                {
                    IPsOfIntrest.Add(selectedmessages[i][3]);
                }
                if (!IPsOfIntrest.Contains(selectedmessages[i][4]))
                {
                    IPsOfIntrest.Add(selectedmessages[i][4]);
                }
            }
        }
    }

    void Flow(bool liveUpdate)
    {
        lock (_locker)
        {
            SelectMessages();
            GetIps();              //get the IP addresses of the selected SIP messages for the top of the screen  and addedto the IPsOfIntrest 
            if (liveUpdate && selectedmessages.Count > prevNumSelectMsg && IPsOfIntrest.Count == prevNumSelectdIPs)         //IF 
            {
                if (selectedmessages.Count > Console.BufferHeight)
                {
                    Console.BufferHeight = Math.Max(Math.Min(10 + selectedmessages.Count, Int16.MaxValue - 1), Console.BufferHeight);
                }
                for (int i = prevNumSelectMsg; i < selectedmessages.Count; i++)
                {
                    fakeCursor[0] = 0; fakeCursor[1] = i + 4;
                    WriteMessageLine(selectedmessages[i], false);
                    WriteLineConsole(new String('-', flowWidth - 1), fieldAttrTxtClr, fieldAttrBkgrdClr);
                }
                prevNumSelectMsg = selectedmessages.Count;
            }
            else
            {
                prevNumSelectMsg = selectedmessages.Count;
                prevNumSelectdIPs = IPsOfIntrest.Count;
                Console.BackgroundColor = fieldConsoleBkgrdClr;
                Console.ForegroundColor = fieldConsoleTxtClr;
                if (!liveUpdate) { ClearConsoleNoTop(); }
                Console.SetCursorPosition(0, 1);
                fakeCursor[0] = 0; fakeCursor[1] = 1;
                if (selectedmessages.Count > Console.BufferHeight)
                {
                    Console.BufferHeight = Math.Max(Math.Min(10 + selectedmessages.Count, Int16.MaxValue - 1), Console.BufferHeight);
                }
                flowWidth = 24;
                WriteConsole(new String(' ', 17), fieldAttrTxtClr, fieldAttrBkgrdClr);
                foreach (string ip in IPsOfIntrest)
                {
                    flowWidth = flowWidth + 29;
                    if (flowWidth > Console.BufferWidth)
                    {
                        Console.BufferWidth = Math.Min(15 + flowWidth, Int16.MaxValue - 1);
                    }
                    WriteConsole(ip + new String(' ', 29 - ip.Length), fieldAttrTxtClr, fieldAttrBkgrdClr);
                }
                WriteLineConsole("", fieldAttrTxtClr, fieldAttrBkgrdClr);
                WriteConsole(new String(' ', 17), fieldAttrTxtClr, fieldAttrBkgrdClr);
                foreach (string ip in IPsOfIntrest)
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
                    WriteConsole(ua + new String(' ', 29 - ua.Length), fieldAttrTxtClr, fieldAttrBkgrdClr);
                }
                WriteLineConsole("", fieldAttrTxtClr, fieldAttrBkgrdClr);
                WriteLineConsole(new String('-', flowWidth - 1), fieldAttrTxtClr, fieldAttrBkgrdClr);
                foreach (string[] msg in selectedmessages)
                {
                    WriteMessageLine(msg, false);
                }
                WriteLineConsole(new String('-', flowWidth - 1), fieldAttrTxtClr, fieldAttrBkgrdClr);
                if (flowSelectPosition > 17) { Console.SetWindowPosition(0, 0); }
                Console.SetCursorPosition(0, flowSelectPosition + 4);
                MessageLine(selectedmessages[flowSelectPosition], true);
                Console.CursorTop -= 1;
            }
        }
    }

    void MessageLine(string[] message, bool invert) // for cursor movement
    {
        //get the index of the src and dst IP
        int srcindx = IPsOfIntrest.IndexOf(message[3]);
        int dstindx = IPsOfIntrest.IndexOf(message[4]);
        bool isright = false;
        int lowindx = 0;
        int hiindx = 0;
        if (srcindx == dstindx)
        {
            string firstline = message[5].Replace("SIP/2.0 ", "");
            string displayedline = firstline.Substring(0, Math.Min(18, firstline.Length)) + message[11];
            string space = new String(' ', 28) + "|";
            if (srcindx == 0)
            {
                string spaceRight = new String(' ', 28 - (int)(Math.Ceiling((decimal)(displayedline.Length / 2)))) + "|";
                if (invert)
                {
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                }
                else
                {
                    Console.BackgroundColor = fieldConsoleBkgrdClr;
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
                Console.Write("{0,-10} {1,-12}", message[1], message[2].Substring(0, 11));
                Console.ForegroundColor = (ConsoleColor)Enum.Parse(typeof(ConsoleColor), message[10]);
                Console.Write(displayedline + "<-");
                if (invert)
                {
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                }
                else
                {
                    Console.BackgroundColor = fieldConsoleBkgrdClr;
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
                Console.Write(new String(' ', 29 - (displayedline.Length + 2)) + "|");
                for (int i = 2; i < IPsOfIntrest.Count; i++)
                {
                    Console.Write(space);
                }
            }
            else
            {
                string spaceLeft = new String(' ', 26 - (int)(Math.Floor((decimal)(displayedline.Length / 2))));
                string spaceRight = new String(' ', 27 - (int)(Math.Ceiling((decimal)(displayedline.Length / 2)))) + "|";
                if (invert)
                {
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                }
                else
                {
                    Console.BackgroundColor = fieldConsoleBkgrdClr;
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
                Console.Write("{0,-10} {1,-12}|", message[1], message[2].Substring(0, 11));
                for (int i = 0; i < srcindx - 1; i++)
                {
                    Console.Write(space);
                }
                Console.Write(spaceLeft);
                Console.ForegroundColor = (ConsoleColor)Enum.Parse(typeof(ConsoleColor), message[10]);
                Console.Write("->" + displayedline + "<-");
                if (invert)
                {
                    Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;
                    Console.ForegroundColor = fieldConsoleTxtInvrtClr;
                }
                else
                {
                    Console.BackgroundColor = fieldConsoleBkgrdClr;
                    Console.ForegroundColor = fieldConsoleTxtClr;
                }
                if (srcindx < IPsOfIntrest.Count - 1)
                {
                    Console.Write(spaceRight);
                    for (int i = srcindx + 2; i < IPsOfIntrest.Count; i++)
                    {
                        Console.Write(space);
                    }
                }
            }
        }
        else
        {
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
                Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;
                Console.ForegroundColor = fieldConsoleTxtInvrtClr;
            }
            else
            {
                Console.BackgroundColor = fieldConsoleBkgrdClr;
                Console.ForegroundColor = fieldConsoleTxtClr;
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
            double rightline = 26 - leftline - displayedline.Length + fullline;
            Console.Write(new String('-', (int)rightline));
            if (isright) { Console.Write(">"); }
            else { Console.Write("-"); }
            if (invert)
            {
                Console.BackgroundColor = fieldConsoleBkgrdInvrtClr;
                Console.ForegroundColor = fieldConsoleTxtInvrtClr;
            }
            else
            {
                Console.BackgroundColor = fieldConsoleBkgrdClr;
                Console.ForegroundColor = fieldConsoleTxtClr;
            }
            Console.Write("|");

            for (int i = 0; i < IPsOfIntrest.Count - 1 - hiindx; i++)
            {
                Console.Write(space);
            }
        }
        if (message[13] != null) { Console.Write(" {0}:{1} {2}", message[13], message[14], message[15]); }
        Console.BackgroundColor = fieldConsoleBkgrdClr;
        Console.ForegroundColor = fieldConsoleTxtClr;
        Console.WriteLine();
    }

    void WriteMessageLine(string[] message, bool invert)
    {
        AttrColor TxtColor;
        AttrColor BkgrdColor;
        AttrColor CallTxtColor;
        //get the index of the src and dst IP
        int srcindx = IPsOfIntrest.IndexOf(message[3]);
        int dstindx = IPsOfIntrest.IndexOf(message[4]);
        bool isright = false;
        int lowindx = 0;
        int hiindx = 0;
        if (srcindx == dstindx)
        {
            string firstline = message[5].Replace("SIP/2.0 ", "");
            string displayedline = firstline.Substring(0, Math.Min(18, firstline.Length)) + message[11];
            string space = new String(' ', 28) + "|";
            if (srcindx == 0)
            {
                string spaceRight = new String(' ', 28 - (int)(Math.Ceiling((decimal)(displayedline.Length / 2)))) + "|";
                if (invert)
                {
                    TxtColor = fieldAttrTxtInvrtClr;
                    BkgrdColor = fieldAttrBkgrdInvrtClr;
                }
                else
                {
                    TxtColor = fieldAttrTxtClr;
                    BkgrdColor = fieldAttrBkgrdClr;
                }
                string formatedStr = String.Format("{0,-10} {1,-12}", message[1], message[2].Substring(0, 11));
                WriteConsole(formatedStr, TxtColor, BkgrdColor);
                CallTxtColor = (AttrColor)Enum.Parse(typeof(AttrColor), message[10]);
                if (htmlFlowToFile)
                {
                    flowFileWriter.Write("<a name = \"flow" + message[0] + "\" href= \"#" + message[0] + "\">");
                }
                WriteConsole(displayedline + "<-", CallTxtColor, BkgrdColor);
                if (htmlFlowToFile)
                {
                    flowFileWriter.Write("</a>");
                }
                WriteConsole(new String(' ', 29 - (displayedline.Length + 2)) + "|", TxtColor, BkgrdColor);
                for (int i = 2; i < IPsOfIntrest.Count; i++)
                {
                    WriteConsole(space, TxtColor, BkgrdColor);
                }
            }
            else
            {
                string spaceLeft = new String(' ', 26 - (int)(Math.Floor((decimal)(displayedline.Length / 2))));
                string spaceRight = new String(' ', 27 - (int)(Math.Ceiling((decimal)(displayedline.Length / 2)))) + "|";
                if (invert)
                {
                    TxtColor = fieldAttrTxtInvrtClr;
                    BkgrdColor = fieldAttrBkgrdInvrtClr;
                }
                else
                {
                    TxtColor = fieldAttrTxtClr;
                    BkgrdColor = fieldAttrBkgrdClr;
                }
                string formatedStr = String.Format("{0,-10} {1,-12}|", message[1], message[2].Substring(0, 11));
                WriteConsole(formatedStr, TxtColor, BkgrdColor);
                for (int i = 0; i < srcindx - 1; i++)
                {
                    WriteConsole(space, TxtColor, BkgrdColor);
                }
                WriteConsole(spaceLeft, TxtColor, BkgrdColor);
                CallTxtColor = (AttrColor)Enum.Parse(typeof(AttrColor), message[10]);
                if (htmlFlowToFile)
                {
                    flowFileWriter.Write("<a name = \"flow" + message[0] + "\" href= \"#" + message[0] + "\">");
                }
                WriteConsole("->" + displayedline + "<-", CallTxtColor, BkgrdColor);
                if (htmlFlowToFile)
                {
                    flowFileWriter.Write("</a>");
                }
                if (srcindx < IPsOfIntrest.Count - 1)
                {
                    WriteConsole(spaceRight, TxtColor, BkgrdColor);
                    for (int i = srcindx + 2; i < IPsOfIntrest.Count; i++)
                    {
                        WriteConsole(space, TxtColor, BkgrdColor);
                    }
                }
            }
        }
        else
        {
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
                TxtColor = fieldAttrTxtInvrtClr;
                BkgrdColor = fieldAttrBkgrdInvrtClr;
            }
            else
            {
                TxtColor = fieldAttrTxtClr;
                BkgrdColor = fieldAttrBkgrdClr;
            }
            string formatedStr = String.Format("{0,-10} {1,-12}|", message[1], message[2].Substring(0, 11));
            WriteConsole(formatedStr, TxtColor, BkgrdColor);
            for (int i = 0; i < lowindx; i++)
            {
                WriteConsole(space, TxtColor, BkgrdColor);
            }
            CallTxtColor = (AttrColor)Enum.Parse(typeof(AttrColor), message[10]);
            if (htmlFlowToFile)
            {
                flowFileWriter.Write("<a name = \"flow" + message[0] + "\" href= \"#" + message[0] + "\">");
            }
            if (isright) { WriteConsole("-", CallTxtColor, BkgrdColor); }
            else { WriteConsole("<", CallTxtColor, BkgrdColor); }
            string firstline = message[5].Replace("SIP/2.0 ", "");
            string displayedline = firstline.Substring(0, Math.Min(18, firstline.Length)) + message[11];
            int fullline = 29 * (hiindx - (lowindx + 1));
            double leftline = ((26 - displayedline.Length) + fullline) / 2; //
            WriteConsole(new String('-', (int)Math.Floor(leftline)), CallTxtColor, BkgrdColor);
            WriteConsole(displayedline, CallTxtColor, BkgrdColor);
            double rightline = 26 - leftline - displayedline.Length + fullline;
            WriteConsole(new String('-', (int)rightline), CallTxtColor, BkgrdColor);
            if (isright) { WriteConsole(">", CallTxtColor, BkgrdColor); }
            else { WriteConsole("-", CallTxtColor, BkgrdColor); }
            if (htmlFlowToFile)
            {
                flowFileWriter.Write("</a>");
            }
            WriteConsole("|", TxtColor, BkgrdColor);
            for (int i = 0; i < IPsOfIntrest.Count - 1 - hiindx; i++)
            {
                WriteConsole(space, TxtColor, BkgrdColor);
            }
        }
        if (message[13] != null)
        {
            String AnotherFrmtStr = String.Format(" {0}:{1} {2}", message[13], message[14], message[15]);
            WriteConsole(AnotherFrmtStr, TxtColor, BkgrdColor);
        }
        WriteLineConsole("", TxtColor, BkgrdColor);
    }

    void FlowSelect()
    {
        prevNumSelectMsg = selectedmessages.Count;
        flowSelectPosition = 0;
        Flow(false);  //display call flow Diagram        
        bool done = false;
        while (done == false)
        {
            ConsoleKeyInfo keypress;
            keypress = Console.ReadKey(true);
            if (keypress.Key == ConsoleKey.DownArrow)
            {
                if (flowSelectPosition < selectedmessages.Count - 1)
                {
                    MessageLine(selectedmessages[flowSelectPosition], false);
                    flowSelectPosition++;
                    MessageLine(selectedmessages[flowSelectPosition], true);
                    Console.CursorTop -= 1;
                }
            }
            else if (keypress.Key == ConsoleKey.PageDown)
            {
                if (flowSelectPosition + 40 < selectedmessages.Count - 1)
                {
                    MessageLine(selectedmessages[flowSelectPosition], false);
                    flowSelectPosition += 40;
                    Console.CursorTop += 39;
                    MessageLine(selectedmessages[flowSelectPosition], true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    MessageLine(selectedmessages[flowSelectPosition], false);
                    flowSelectPosition = selectedmessages.Count - 1;
                    Console.CursorTop = selectedmessages.Count - 1 + 4;
                    MessageLine(selectedmessages[flowSelectPosition], true);
                    Console.CursorTop -= 1;
                }
            }
            else if (keypress.Key == ConsoleKey.UpArrow)
            {
                if (flowSelectPosition > 0)
                {
                    MessageLine(selectedmessages[flowSelectPosition], false);
                    Console.CursorTop -= 2;
                    flowSelectPosition--;
                    MessageLine(selectedmessages[flowSelectPosition], true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    Console.SetCursorPosition(0, 0);   //brings window to the very top
                    Console.SetCursorPosition(0, 4);
                }
            }
            else if (keypress.Key == ConsoleKey.PageUp)
            {
                if (flowSelectPosition > 39)
                {
                    MessageLine(selectedmessages[flowSelectPosition], false);
                    Console.CursorTop -= 41;
                    flowSelectPosition -= 40;
                    MessageLine(selectedmessages[flowSelectPosition], true);
                    Console.CursorTop -= 1;
                }
                else
                {
                    MessageLine(selectedmessages[flowSelectPosition], false);
                    Console.CursorTop = 4;
                    flowSelectPosition = 0;
                    MessageLine(selectedmessages[flowSelectPosition], true);
                    Console.CursorTop -= 1;
                }
                if (flowSelectPosition == 0)
                {
                    Console.SetCursorPosition(0, 0);   //brings window to the very top
                    Console.SetCursorPosition(0, 4);
                }
            }
            else if ((keypress.Key == ConsoleKey.Enter) || (keypress.Key == ConsoleKey.Spacebar))
            {
                DisplayMessage(flowSelectPosition, selectedmessages);
                Flow(false);  //display call flow Diagram
            }
            else if (keypress.Key == ConsoleKey.Escape)
            {
                done = true;
            }
            else if (keypress.Key == ConsoleKey.D)
            {
                if (dupIP)
                {
                    dupIP = false;
                }
                else
                {
                    dupIP = true;
                }
                flowSelectPosition = 0;
                Flow(false);  //display call flow Diagram
            }
            else if (keypress.Key == ConsoleKey.O)
            {
                lock (_locker)
                {
                    Console.ForegroundColor = msgBoxTxt;
                    Console.BackgroundColor = msgBoxBkgrd;
                    int center = Math.Max(0, (int)Math.Floor((decimal)((Console.WindowWidth - 136) / 2)));
                    Console.CursorLeft = center; Console.WriteLine(@"+---------------------------------------------------------------------------+\ ");
                    Console.CursorLeft = center; Console.WriteLine(@"| Enter the file name to the data will be writen to (.html for html output) | |");
                    Console.CursorLeft = center; Console.WriteLine(@"|                                                                           | |");
                    Console.CursorLeft = center; Console.WriteLine(@"+---------------------------------------------------------------------------+ |");
                    Console.CursorLeft = center; Console.WriteLine(@" \___________________________________________________________________________\|");
                    Console.CursorTop -= 3;
                    Console.CursorLeft = center + 2;
                    string writeFileName = Console.ReadLine();
                    if (String.IsNullOrEmpty(writeFileName))
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.CursorTop = Console.CursorTop - 1;
                        Console.CursorLeft = center;
                        Console.WriteLine("| No file name was entered. Press any key to continue");
                        Console.ForegroundColor = fieldConsoleTxtClr;
                        Console.CursorVisible = true;
                        Console.ReadKey(true);
                        Console.CursorTop -= 4;
                    }
                    else
                    {
                        if (Regex.IsMatch(writeFileName, @"^.*\.html$")) { htmlFlowToFile = true; }
                        try
                        {
                            // Attempt to open output file.
                            flowFileWriter = new StreamWriter(writeFileName);
                        }
                        catch (IOException e)
                        {
                            TextWriter errorWriter = Console.Error;
                            errorWriter.WriteLine(e.Message);
                        }
                        writeFlowToFile = true;
                        if (htmlFlowToFile)
                        {
                            flowFileWriter.WriteLine("<!DOCTYPE html>");
                            flowFileWriter.WriteLine("<html>");
                            flowFileWriter.WriteLine("<head>");
                            flowFileWriter.WriteLine("<style> a:link {text-decoration: none} </style>");
                            flowFileWriter.WriteLine("<font face=\"Courier\" >");
                            flowFileWriter.WriteLine("</head>");
                            flowFileWriter.WriteLine("<body>");
                            flowFileWriter.WriteLine("<pre>");
                        }
                        Flow(false);  //display call flow Diagram
                        flowFileWriter.WriteLine(" ");
                        flowFileWriter.WriteLine(" ");
                        List<String> filesToRead = new List<String>();
                        //get all the file names in a list
                        for (int i = 0; i < selectedmessages.Count; i++) 
                        {
                            if (!filesToRead.Contains(selectedmessages[i][12]))
                            {
                                filesToRead.Add((selectedmessages[i][12]));
                            }
                        }
                        Console.SetCursorPosition(0, 1);
                        Console.SetWindowPosition(0, 0);
                        //open each filename in the list 
                        foreach (string fileToReadName in filesToRead)
                        {
                            long fileLineNum = 0;
                            long progress = 0;
                            using (StreamReader sr = new StreamReader(fileToReadName))
                            {
                                 //cycle through all the seleted msg 
                                for (int i = 0; i < selectedmessages.Count; i++)
                                {
                                    //find the selected messages that match the file name that is open
                                    if (selectedmessages[i][12]== fileToReadName)
                                    {
                                        //advance the read position to the first line of the message
                                        Console.Write("Seeking to line " + selectedmessages[i][0] + " in file " + Regex.Match(fileToReadName, @"^.*(\\.*)$").Groups[1].ToString());
                                        string line = "";
                                        for (long j = fileLineNum; j < Int32.Parse(selectedmessages[i][0]); j++)
                                        {
                                            progress++;
                                            if (progress == 10000)
                                            {
                                                Console.Write(".");
                                                progress = 0;
                                            }
                                            line = sr.ReadLine();
                                            fileLineNum++;
                                        }
                                        Console.WriteLine();                                        
                                        if (htmlFlowToFile)
                                        {
                                            // html tag to link to by msg start index number
                                            flowFileWriter.Write("<a name = \"" + selectedmessages[i][0] + "\">");
                                            flowFileWriter.WriteLine(WebUtility.HtmlEncode(line));
                                        }
                                        else
                                        {
                                            flowFileWriter.WriteLine(line);
                                        }
                                        // from read file to write file line of message to end index
                                        for (long j = fileLineNum; j < Int64.Parse(selectedmessages[i][9]) - 1; j++) 
                                        {
                                            if (htmlFlowToFile)
                                            {
                                                flowFileWriter.WriteLine(WebUtility.HtmlEncode(sr.ReadLine()));
                                            }
                                            else
                                            {
                                                flowFileWriter.WriteLine(sr.ReadLine());
                                            }
                                            fileLineNum++;
                                        }
                                        if (htmlFlowToFile)
                                        {
                                            flowFileWriter.Write("</a>");
                                            flowFileWriter.Write("<a href= \"#flow" + selectedmessages[i][0] + "\">Back</a>");
                                            flowFileWriter.WriteLine("</br>");
                                            flowFileWriter.WriteLine("<hr>");
                                            flowFileWriter.WriteLine("</br>");
                                        }
                                    }
                                }
                                sr.Close();
                            }
                        }
                        if (htmlFlowToFile)
                        {
                            flowFileWriter.WriteLine("</pre>");
                            flowFileWriter.WriteLine("</body>");
                            flowFileWriter.WriteLine("</html>");
                        }
                        htmlFlowToFile = false;
                        writeFlowToFile = false;
                        flowFileWriter.Close();                        
                    }
                    Flow(false);  //display call flow Diagram
                }
            }
        }
        return;
    }

    void DisplayMessage(int msgindxselected, List<string[]> messages)
    {
        int msgStartIdx = Int32.Parse(messages[msgindxselected][0]);
        int msgEndIdx = Int32.Parse(messages[msgindxselected][9]);
        if ((msgEndIdx - msgStartIdx) > Console.BufferHeight)
        {
            Console.BufferHeight = Math.Max(Math.Min(5 + (Int16)(msgEndIdx - msgStartIdx), Int16.MaxValue - 1), Console.BufferHeight);
        }
        ClearConsoleNoTop();
        Console.SetCursorPosition(0, 1);
        fakeCursor[0] = 0; fakeCursor[1] = 1;
        Console.WriteLine("From line " + messages[msgindxselected][0] + " to " + messages[msgindxselected][9] + " from file " + messages[msgindxselected][12]);
        using (StreamReader sr = new StreamReader(messages[msgindxselected][12]))
        {
            string line = "";
            Console.Write("Finding lines from file");
            long progress = 0;
            for (int i = 0; i < msgStartIdx; i++)
            {
                progress++;
                if (progress == 10000)
                {
                    Console.Write(".");
                    progress = 0;
                }
                line = sr.ReadLine();
            }
            if (writeFlowToFile)
            {
                flowFileWriter.Write("<a name = \"" + messages[msgindxselected][0] + "\">");
                flowFileWriter.WriteLine(line);
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine(line);
            }
            for (int j = msgStartIdx; j < msgEndIdx - 1; j++)
            {
                if (writeFlowToFile)
                {
                    flowFileWriter.WriteLine(sr.ReadLine());
                }
                else
                {
                    Console.WriteLine(sr.ReadLine());
                }
            }
            if (writeFlowToFile)
            {
                flowFileWriter.Write("</a>");
                flowFileWriter.Write("<a href= \"#flow" + messages[msgindxselected][0] + "\">Back</a>");
                flowFileWriter.WriteLine("</br>");
                flowFileWriter.WriteLine("<hr>");
                flowFileWriter.WriteLine("</br>");
            }
            sr.Close();
        }
        Console.SetCursorPosition(0, 1);
        fakeCursor[0] = 0; fakeCursor[1] = 1;
        ConsoleKeyInfo keypressed;
        while (!writeFlowToFile && !((keypressed = Console.ReadKey(true)).Key == ConsoleKey.Escape))
        {
            if (Console.CursorTop < Console.BufferHeight - 1 && keypressed.Key == ConsoleKey.DownArrow)
            {
                Console.CursorTop++;
            }
            if (Console.CursorTop > 0 && keypressed.Key == ConsoleKey.UpArrow)
            {
                Console.CursorTop--;
            }
        }
    }

    void ListAllMsg(string regexStr)
    {
        List<string[]> filtered = new List<string[]>();
        bool done = false;
        int position = 0;
        int MsgLineLen;
        int match = 0;
        string strginput;
        ClearConsoleNoTop();
        if (regexStr == null)
        {
            Console.SetCursorPosition(0, 1);
            Console.WriteLine("Enter regex to search. Max lines displayed are 32765. example: for all the msg to/from 10.28.160.42 at 16:40:11 use 16:40:11.*10.28.160.42");
            Console.WriteLine("Data format: line number|date|time|src IP|dst IP|first line of SIP msg|From:|To:|Call-ID|line number|color|has SDP|filename|SDP IP|SDP port|SDP codec|useragent|cseq");
            strginput = Console.ReadLine();
        }
        else
        {
            strginput = regexStr;
        }
        ClearConsoleNoTop();
        Console.SetCursorPosition(0, 1);
        fakeCursor[0] = 0; fakeCursor[1] = 1;
        if (string.IsNullOrEmpty(strginput))
        {
            Console.WriteLine("You must enter a regex");
            Console.ReadKey(true);
            done = true;
        }
        else
        {
            Regex regexinput = new Regex(strginput);
            for (int i = 0; i < Math.Min(messages.Count, Int16.MaxValue - 2); i++)
            {
                string[] ary = messages[i];
                if (regexinput.IsMatch(string.Join(" ", ary)))
                {
                    match++;
                    if (match + 1 > Console.BufferHeight)
                    {
                        if (match < Int16.MaxValue - 100 + 1)
                        {
                            Console.BufferHeight = match + 100 + 1;
                        }
                        else
                        {
                            Console.BufferHeight = match + 1;
                        }
                    }
                    MsgLineLen = string.Join(" ", ary).Length + 28;
                    if (MsgLineLen >= Console.BufferWidth) { Console.BufferWidth = MsgLineLen + 1; }
                    WriteLineConsole(String.Format("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", ary), fieldAttrTxtClr, fieldAttrBkgrdClr);
                    filtered.Add(ary);
                }
            }
            if (filtered.Count == 0)
            {
                Console.WriteLine("NO search matches found. Press any key to continue");
                Console.ReadKey(true);
                return;
            }
            Console.SetCursorPosition(0, 1);
            Console.BackgroundColor = fieldConsoleTxtClr;
            Console.ForegroundColor = fieldConsoleBkgrdClr;
            Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", filtered[position]);
            Console.CursorTop -= 1;
            Console.BackgroundColor = fieldConsoleBkgrdClr;
            Console.ForegroundColor = fieldConsoleTxtClr;
        }
        while (!done)
        {
            ConsoleKeyInfo keypressed = Console.ReadKey(true);
            switch (keypressed.Key)
            {
                case ConsoleKey.DownArrow:
                    if (position < filtered.Count - 1)
                    {
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", filtered[position]);
                        position++;
                        Console.BackgroundColor = fieldConsoleTxtClr;
                        Console.ForegroundColor = fieldConsoleBkgrdClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                    }
                    break;

                case ConsoleKey.PageDown:
                    if (position + 40 < filtered.Count - 1)
                    {
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", filtered[position]);
                        Console.CursorTop += 39;
                        position += 40;
                        Console.BackgroundColor = fieldConsoleTxtClr;
                        Console.ForegroundColor = fieldConsoleBkgrdClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                    }
                    break;

                case ConsoleKey.UpArrow:
                    if (position > 0)
                    {
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", filtered[position]);
                        position--;
                        Console.CursorTop -= 2;
                        Console.BackgroundColor = fieldConsoleTxtClr;
                        Console.ForegroundColor = fieldConsoleBkgrdClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                    }
                    break;
                case ConsoleKey.PageUp:
                    if (position > 39)
                    {
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", filtered[position]);
                        position -= 40;
                        Console.CursorTop -= 41;
                        Console.BackgroundColor = fieldConsoleTxtClr;
                        Console.ForegroundColor = fieldConsoleBkgrdClr;
                        Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", filtered[position]);
                        Console.CursorTop -= 1;
                        Console.BackgroundColor = fieldConsoleBkgrdClr;
                        Console.ForegroundColor = fieldConsoleTxtClr;
                    }
                    break;

                case ConsoleKey.Enter:
                    DisplayMessage(position, filtered);
                    Console.Clear();
                    Console.SetCursorPosition(0, 0);
                    foreach (string[] line in filtered)
                    {
                        WriteLineConsole(String.Format("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", line), fieldAttrTxtClr, fieldAttrBkgrdClr);
                    }
                    Console.SetCursorPosition(0, position + 1);
                    Console.BackgroundColor = fieldConsoleTxtClr;
                    Console.ForegroundColor = fieldConsoleBkgrdClr;
                    Console.WriteLine("{0,-7}{1,-11}{2,-16}{3,-16}{4,-16}{5} From:{8} To:{7} {6} {9} {10} {11} {12} {13} {14} {15} {16} {17}", filtered[position]);
                    Console.CursorTop = Console.CursorTop - 1;
                    Console.BackgroundColor = fieldConsoleBkgrdClr;
                    Console.ForegroundColor = fieldConsoleTxtClr;
                    break;

                case ConsoleKey.Escape:
                    done = true;
                    break;
            }
        }
    }
}

public class ConsoleBuffer
{

    private static SafeFileHandle _hBuffer = null;

    static ConsoleBuffer()
    {
        const int STD_OUTPUT_HANDLE = -11;
        _hBuffer = GetStdHandle(STD_OUTPUT_HANDLE);
        if (_hBuffer.IsInvalid)
        {
            throw new Exception("Failed to open console buffer");
        }
    }

    public static void WriteAt(short x, short y, string value)
    {
        int n = 0;
        WriteConsoleOutputCharacter(_hBuffer, value, value.Length, new Coord(x, y), ref n);
    }

    public static void SetAttribute(short x, short y, int length, short attr)
    {
        short[] attrAry = new short[length];
        for (int i = 0; i < length; i++)
        {
            attrAry[i] = attr;
        }
        SetAttribute(x, y, length, attrAry);
    }

    public static void SetAttribute(short x, short y, int length, short[] attrs)
    {
        int n = 0;
        WriteConsoleOutputAttribute(_hBuffer, attrs, length, new Coord(x, y), ref n);
    }


    [DllImport("kernel32.dll", SetLastError = true)]
    static extern SafeFileHandle GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteConsoleOutput(
      SafeFileHandle hConsoleOutput,
      CharInfo[] lpBuffer,
      Coord dwBufferSize,
      Coord dwBufferCoord,
      ref SmallRect lpWriteRegion);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteConsoleOutputCharacter(
      SafeFileHandle hConsoleOutput,
      string lpCharacter,
      int nLength,
      Coord dwWriteCoord,
      ref int lpumberOfCharsWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteConsoleOutputAttribute(
      SafeFileHandle hConsoleOutput,
      short[] lpAttributes,
      int nLength,
      Coord dwWriteCoord,
      ref int lpumberOfAttrsWritten);

    [StructLayout(LayoutKind.Sequential)]
    struct Coord
    {
        public short X;
        public short Y;

        public Coord(short X, short Y)
        {
            this.X = X;
            this.Y = Y;
        }
    };

    [StructLayout(LayoutKind.Explicit)]
    struct CharUnion
    {
        [FieldOffset(0)]
        public char UnicodeChar;
        [FieldOffset(0)]
        public byte AsciiChar;
    }

    [StructLayout(LayoutKind.Explicit)]
    struct CharInfo
    {
        [FieldOffset(0)]
        public CharUnion Char;
        [FieldOffset(2)]
        public short Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SmallRect
    {
        public short Left;
        public short Top;
        public short Right;
        public short Bottom;
    }
   
}
