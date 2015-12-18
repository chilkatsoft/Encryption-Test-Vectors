using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Encryption_Test_Vectors
    {
    public partial class Form1 : Form
	{
	public Form1()
	    {
	    InitializeComponent();
	    }

	private bool testBlowfishVectors()
	    {
	    // Test a CBC vector from https://www.schneier.com/code/vectors.txt

	    //chaining mode test data
	    //key[16]   = 0123456789ABCDEFF0E1D2C3B4A59687
	    //iv[8]     = FEDCBA9876543210
	    //data[29]  = "7654321 Now is the time for " (includes trailing '\0')
	    //data[29]  = 37363534333231204E6F77206973207468652074696D6520666F722000
	    //cbc cipher text
	    //cipher[32]= 6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC

	    Chilkat.Crypt2 crypt = new Chilkat.Crypt2();

	    crypt.CryptAlgorithm    = "blowfish2";
	    crypt.CipherMode        = "cbc";
	    crypt.PaddingScheme     = 3;	// It is not explicitly stated, but the padding is with NULL bytes.
	    crypt.KeyLength         = 128;

	    string pt = "7654321 Now is the time for ";
	    byte[] ptBytes = System.Text.Encoding.UTF8.GetBytes(pt);
	    int len = ptBytes.Length;
	    Array.Resize(ref ptBytes,len+1);
	    ptBytes[len] = 0;

	    byte[] ivBytes = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	    string ivHex = crypt.Encode(ivBytes,"hex");
	    crypt.SetEncodedIV(ivHex,"hex");
  
	    crypt.SetEncodedKey("0123456789ABCDEFF0E1D2C3B4A59687", "hex");
	    byte[] ctBytes = crypt.EncryptBytes(ptBytes);

	    string ct = crypt.Encode(ctBytes,"hex");
	    string ctExpected = "6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC";

	    if (!ct.Equals(ctExpected,StringComparison.OrdinalIgnoreCase))
		{
		textBox1.Text = "Blowfish test vector result does not match!\r\n" +
		    "ct            = " + ct + " (" + ct.Length.ToString() + ")\r\n" +
		    "ctExpected = " + ctExpected + " (" + ctExpected.Length.ToString() + ")\r\n";
		return false;
		}

	    return true;
	    }

	private void button1_Click(object sender, EventArgs e)
	    {
	    
	    bool success = testBlowfishVectors();
	    if (success) textBox1.Text = "Success.";
	    }

	private void Form1_Load(object sender, EventArgs e)
	    {
	    Chilkat.Global glob = new Chilkat.Global();
	    bool success = glob.UnlockBundle("Anything for 30-day trial");
	    if (!success) textBox1.Text = "Unlock failed.";
	    }
	}
    }
