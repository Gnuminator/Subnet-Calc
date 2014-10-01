using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Net;

namespace Subnetting
{


    public struct IPAdress
    {
        // Creates the variables a,b,c,d.
        public byte a;
        public byte b;
        public byte c;
        public byte d;

        // Stores the values of the bytes into 4 different variables, for further use.
        // Binary anding with hex values used to make sure that whatever value recieved or entered, it cannot be more than 0-255
        public IPAdress(uint Value)
        {
            byte _a = (byte)((Value >> 24) & 0x000000FF);
            byte _b = (byte)((Value >> 16) & 0x000000FF);
            byte _c = (byte)((Value >> 8) & 0x000000FF);
            byte _d = (byte)((Value >> 0) & 0x000000FF);
            a = _a;
            b = _b;
            c = _c;
            d = _d;
        }

        //Combines the 4 variables to one, making a complete address.
        public uint Value
        {
            get
            {
                uint _a = (((uint)a) << 24) | (((uint)b) << 16) | (((uint)c) << 8) | (((uint)d) << 0);
                return _a;
            }
        }

        // New function Class, checks what the IP's network class is.
        public string Class
        {
            get
            {
                if (a <= 127)
                {
                    return "A";
                }
                else if (a <= 191)
                {
                    return "B";
                }
                else if (a <= 223)
                {
                    return "C";
                }
                else if (a <= 239)
                {
                    return "D";
                }
                else if (a <= 255)
                {
                    return "E";
                }
                else
                {
                    return "0";
                }
            }
        }


        public static bool TryParse(string input, out IPAdress adress)
        {
            try
            {
                // Looking for a match in the input, where @ means that you dont need to replace \ with \\ in the string
                // d represents numbers between 0-9
                // the + after d matches if the number(s) is between 0-9 (in our case 0-255)
                // the paranthethes means that we want to capture the result, where the \. means you want to match against a dot.
                //The captured numbers are stored in math.Groups[n].Value
                var match = Regex.Match(input, @"(\d+)\.(\d+)\.(\d+)\.(\d+)");
                if (match.Success)
                {

                    byte _a = byte.Parse(match.Groups[1].Value);
                    byte _b = byte.Parse(match.Groups[2].Value);
                    byte _c = byte.Parse(match.Groups[3].Value);
                    byte _d = byte.Parse(match.Groups[4].Value);

                    //Uses the captured values to store them to the ip address var
                    adress = new IPAdress() { a = _a, b = _b, c = _c, d = _d };
                    return true;
                }

                adress = new IPAdress() { a = 0, b = 0, c = 0, d = 0 };
                return false;
            }
            catch (Exception ex)
            {
                adress = new IPAdress() { a = 0, b = 0, c = 0, d = 0 };
                return false;
            }
        }

        // Collects the data that was inputted, to create a string, making the IP address.
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendFormat("{0}.{1}.{2}.{3}", a, b, c, d);
            return builder.ToString();
        }
        // 
        public string ToString(string format)
        {
            if (format == "B")
            {
                StringBuilder builder = new StringBuilder();
                builder.AppendFormat("{0}.{1}.{2}.{3}",
                    Convert.ToString(a, 2).PadLeft(8, '0'),
                    Convert.ToString(b, 2).PadLeft(8, '0'),
                    Convert.ToString(c, 2).PadLeft(8, '0'),
                    Convert.ToString(d, 2).PadLeft(8, '0')
                );
                return builder.ToString();
            }
            else
            {
                return ToString();
            }
        }


    };

    // Creates the variables going to be used for subnetmask address
    public struct SubnetAdress
    {
        public byte a;
        public byte b;
        public byte c;
        public byte d;

        public static bool TryParse(string input, out SubnetAdress adress)
        {
            try
            {
                // Regex matching the subnet mask, so it cannot be wrong.
                // Also parses this info into match.groups
                var match = Regex.Match(input, @"(\d+)\.(\d+)\.(\d+)\.(\d+)");
                var match2 = Regex.Match(input, @"/(\d+)");

                if (match.Success)
                {
                    byte _a = byte.Parse(match.Groups[1].Value);
                    byte _b = byte.Parse(match.Groups[2].Value);
                    byte _c = byte.Parse(match.Groups[3].Value);
                    byte _d = byte.Parse(match.Groups[4].Value);

                    adress = new SubnetAdress() { a = _a, b = _b, c = _c, d = _d };
                    return true;
                }
                else if (match2.Success)
                {
                    // Error checks the length of the subnet address.
                    byte _e = byte.Parse(match2.Groups[1].Value);
                    if (_e < 0) throw new ArgumentOutOfRangeException();
                    if (_e > 32) throw new ArgumentOutOfRangeException();

                    //TODO: Validate this behaviour against big endian machines.
                    // Has not been completed, but what this does is check whether the input -
                    // is using big or little endian, and then updates the variable accordingly.
                    // As this is not updated, it will just consider little endian, as a normal IP address would be.
                    uint subnetMask = 0xFFFFFFFF << (32 - _e);
                    if (BitConverter.IsLittleEndian)
                    {
                        byte _a = (byte)((subnetMask >> 24) & 0x000000FF);
                        byte _b = (byte)((subnetMask >> 16) & 0x000000FF);
                        byte _c = (byte)((subnetMask >> 8) & 0x000000FF);
                        byte _d = (byte)((subnetMask >> 0) & 0x000000FF);
                        adress = new SubnetAdress() { a = _a, b = _b, c = _c, d = _d };
                        return true;
                    }
                    else
                    {
                        byte _a = (byte)((subnetMask >> 0) & 0x000000FF);
                        byte _b = (byte)((subnetMask >> 8) & 0x000000FF);
                        byte _c = (byte)((subnetMask >> 16) & 0x000000FF);
                        byte _d = (byte)((subnetMask >> 24) & 0x000000FF);
                        adress = new SubnetAdress() { a = _a, b = _b, c = _c, d = _d };
                        return true;
                    }
                }


                adress = new SubnetAdress() { a = 0, b = 0, c = 0, d = 0 };
                return false;
            }
            catch (Exception ex)
            {
                adress = new SubnetAdress() { a = 0, b = 0, c = 0, d = 0 };
                return false;
            }
        }



        public uint Value
        {
            get
            {
                uint _a = (((uint)a) << 24) | (((uint)b) << 16) | (((uint)c) << 8) | (((uint)d) << 0);
                return _a;
            }
        }

        public int SubnetMask
        {
            get
            {
                // Returns how many bits is a part of the subnetmask.
                int _d = 0;
                uint _a = (((uint)a) << 24) | (((uint)b) << 16) | (((uint)c) << 8) | (((uint)d) << 0);
                for (int i = 0; i < 32; i++)
                {
                    uint _b = 1; _b <<= i;
                    if ((_a & _b) == 0)
                    {
                        _d++;
                    }
                    else
                    {
                        break;
                    }
                }

                return 32 - _d;
            }
        }

        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendFormat("{0}.{1}.{2}.{3}", a, b, c, d);
            return builder.ToString();
        }

        public string ToString(string format)
        {
            if (format == "B")
            {

                StringBuilder builder = new StringBuilder();
                builder.AppendFormat("{0}.{1}.{2}.{3}",
                    Convert.ToString(a, 2).PadLeft(8, '0'),
                    Convert.ToString(b, 2).PadLeft(8, '0'),
                    Convert.ToString(c, 2).PadLeft(8, '0'),
                    Convert.ToString(d, 2).PadLeft(8, '0')
                );
                return builder.ToString();
            }
            else
            {
                return ToString();
            }
        }
    };


    public struct NetworkAdress
    {
        public IPAdress adress;
        public SubnetAdress mask;


        public int AvailableSubnets
        {
            get
            {
                // Calculates the subnet mask, using the ip class as a reference.
                switch (adress.Class)
                {
                    case "A": return ((int)Math.Pow(2, (mask.SubnetMask - 8)));
                    case "B": return ((int)Math.Pow(2, (mask.SubnetMask - 16)));
                    case "C": return ((int)Math.Pow(2, (mask.SubnetMask - 24)));
                    case "D": return ((int)Math.Pow(2, (mask.SubnetMask - 24)));
                    case "E": return ((int)Math.Pow(2, (mask.SubnetMask - 24)));
                }

                return 0;
            }
        }

        // Uses the subnetmask to calculate how many hosts there is available on each subnet
        // Also finds the first and last usable host address on each subnet, using the values from above comment.
        public int AvailableHostAdresses
        {
            get
            {
                return ((int)Math.Pow(2, (32 - mask.SubnetMask))) - 2;
            }
        }

        public IPAdress FirstHost
        {
            get
            {
                uint v = (adress.Value & (mask.Value)) | 1;
                return new IPAdress(v);
            }
        }

        public IPAdress LastHost
        {
            get
            {
                uint v = (adress.Value & (mask.Value)) | ((~mask.Value) & 0xFFFFFFFE);
                return new IPAdress(v);
            }
        }

        public IPAdress Network
        {
            get
            {
                uint v = adress.Value & (mask.Value);
                return new IPAdress(v);
            }
        }

        public IPAdress Broadcast
        {
            get
            {
                uint v = (adress.Value & (mask.Value)) | (~mask.Value);
                return new IPAdress(v);
            }
        }

        // Uses regex to match the ip address, and calculates the network address for the Ip, using tryparse in match.groups
        public static bool TryParse(string input, out NetworkAdress adress)
        {
            var match = Regex.Match(input, @"((?:\d+)\.(?:\d+)\.(?:\d+)\.(?:\d+)) ((?:\d+)\.(?:\d+)\.(?:\d+)\.(?:\d+))");
            var match2 = Regex.Match(input, @"((?:\d+)\.(?:\d+)\.(?:\d+)\.(?:\d+))(\/\d+)");


            if (match.Success)
            {
                adress = new NetworkAdress();
                return true & IPAdress.TryParse(match.Groups[1].Value, out adress.adress) & SubnetAdress.TryParse(match.Groups[2].Value, out adress.mask);
            }
            else if (match2.Success)
            {
                adress = new NetworkAdress();
                return true & IPAdress.TryParse(match2.Groups[1].Value, out adress.adress) & SubnetAdress.TryParse(match2.Groups[2].Value, out adress.mask);
            }

            adress = new NetworkAdress();
            return false;
        }

        // converts the input/subnetmask to a string, with a proper format (xxx.xxx.xxx.xxx), 
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendFormat("{0}.{1}.{2}.{3}", adress.a, adress.b, adress.c, adress.d);
            builder.Append(' ');
            builder.AppendFormat("{0}.{1}.{2}.{3}", mask.a, mask.b, mask.c, mask.d);
            return builder.ToString();
        }

        // 
        public string ToString(string format)
        {
            if (format == "B")
            {
                // Convert IP Addressen og Subnetmasken til binær
                StringBuilder builder = new StringBuilder();
                builder.AppendFormat("{0}.{1}.{2}.{3}",
                    Convert.ToString(adress.a, 2).PadLeft(8, '0'),
                    Convert.ToString(adress.b, 2).PadLeft(8, '0'),
                    Convert.ToString(adress.c, 2).PadLeft(8, '0'),
                    Convert.ToString(adress.d, 2).PadLeft(8, '0')
                );
                builder.Append(' ');
                builder.AppendFormat("{0}.{1}.{2}.{3}",
                    Convert.ToString(mask.a, 2).PadLeft(8, '0'),
                    Convert.ToString(mask.b, 2).PadLeft(8, '0'),
                    Convert.ToString(mask.c, 2).PadLeft(8, '0'),
                    Convert.ToString(mask.d, 2).PadLeft(8, '0')
                );
                return builder.ToString();
            }
            else
            {
                return ToString();
            }
        }
    };

    public class SubnetCalculator
    {



        // Petition to enter a valid Ip address, 
        public string Calculate(string IP)
        {
            
            bool result = false;
            var sb = new StringBuilder();
            
            

                //Checks if everything is correct, then parses the result into the console
                NetworkAdress addr;
                result = NetworkAdress.TryParse(/*"192.168.0.1/24"*/ IP, out addr);
                if (result == true)
                {
                   
                    // Results with helptexts
                    sb.Append("Network Class "+addr.adress.Class +" \nThis is the IP address' class.");
                    sb.AppendLine();
                    sb.AppendLine();
                    sb.Append("Network Prefix "+addr.mask.SubnetMask.ToString()+" \nThis is the number which represent the set amount of network bits reserved.");
                    sb.AppendLine();
                    sb.AppendLine();
                    sb.Append("Network Address "+addr.adress.ToString()+"");
                    sb.AppendLine();
                    sb.AppendLine();
                    sb.Append("Network Subnetmask "+addr.mask.ToString()+" \nThis is the subnets subnetmask (NOT default).");
                    sb.AppendLine();
                    sb.AppendLine();
                    sb.Append("First Usable Host "+addr.FirstHost.ToString()+" \nThe first usable host address in the subnets range.");
                    sb.AppendLine();
                    sb.AppendLine();
                    sb.Append("Last Usable Host "+addr.LastHost.ToString()+" \nThe last usable host address in the subnets range.");
                    sb.AppendLine();
                    sb.AppendLine();
                    sb.Append("Network Subnet ID "+addr.Network.ToString()+"");
                    sb.AppendLine();
                    sb.Append("Network Broadcast Address "+addr.Broadcast.ToString()+"");
                    sb.AppendLine();
                    sb.Append("Network Adress in Binary "+addr.adress.ToString("B")+"");
                    sb.AppendLine();
                    sb.Append("Network Mask in Binary "+addr.mask.ToString("B")+"");
                    sb.AppendLine();
                    sb.Append("Network Subnets Available: "+addr.AvailableSubnets+"");
                    sb.AppendLine();
                    sb.Append("Network Hosts Available: "+addr.AvailableHostAdresses+"");
                    sb.AppendLine();
                }
                else
                {
                    
                    // If the IP address isnt correct, gives this error.
                    return "Error while parsing.\nPlease enter a valid IP address;";
                }
           
           
            return sb.ToString();
        }
    }
}