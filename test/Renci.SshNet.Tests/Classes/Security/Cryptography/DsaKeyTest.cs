﻿using System;
using System.Security.Cryptography;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using Renci.SshNet.Security;
using Renci.SshNet.Tests.Common;

namespace Renci.SshNet.Tests.Classes.Security.Cryptography
{
    [TestClass]
    public class DsaKeyTest : TestBase
    {
        private static DsaKey GetDsaKey(string fileName, string passPhrase = null)
        {
            using (var stream = GetData(fileName))
            {
                return (DsaKey)new PrivateKeyFile(stream, passPhrase).Key;
            }
        }

        // This is just to line up any differences in the assertion message.
        private static void AssertEqual(byte[] actualBytes, string expectedHex)
        {
            string actualHex = BitConverter.ToString(actualBytes).Replace("-", "");

            Assert.AreEqual(expectedHex, actualHex,
                $"{Environment.NewLine}Expected: {expectedHex}{Environment.NewLine}  Actual: {actualHex}");
        }

        // These tests generated by converting the keys to PKCS8, importing them to BCL DSA,
        // and printing out the expected DSAParameter values.

        // Some useful commands:

        // Generate a new params file with specific parameters:
        // openssl genpkey -genparam -algorithm dsa -pkeyopt pbits:1024 -pkeyopt qbits:160 -out dsa.1024.params

        // Generate PKCS8 key file from the params:
        // openssl genpkey -paramfile dsa.1024.params -out dsa.1024.txt

        // Convert to PKCS1:
        // openssl pkcs8 -in dsa.1024.txt -nocrypt -traditional -out dsa.1024.pkcs1.txt

        // Convert PKCS1 to ssh.com:
        // puttygen dsa.1024.pkcs1.txt -O private-sshcom -o dsa.1024.ssh2.txt

        // Convert to PKCS8:
        // openssl pkcs8 -topk8 -nocrypt -in Key.DSA.txt -out Key.DSA.PKCS8.txt

        /*
        
        using IndentedTextWriter tw = new(Console.Out);

        foreach (string filePath in Directory.EnumerateFiles(dir, "*.DSA.*txt"))
        {
            string pkFile = Path.GetFileNameWithoutExtension(filePath);

            tw.WriteLine("[TestMethod]");
            tw.WriteLine($"public void {pkFile.Replace('.', '_')}()");
            tw.WriteLine("{");
            tw.Indent++;
    
            tw.WriteLine($"DsaKey dsaKey = GetDsaKey(\"{pkFile}.txt\");");
            tw.WriteLine();
            tw.WriteLine("DSAParameters p = dsaKey.GetDSAParameters();");
            tw.WriteLine();

            using DSA dsa = DSA.Create();

            dsa.ImportFromPem(File.ReadAllText(filePath));
    
            DSAParameters p = dsa.ExportParameters(true);

            WriteParamAssert(p.P);
            WriteParamAssert(p.G);
            WriteParamAssert(p.Y);
            WriteParamAssert(p.Q);
            WriteParamAssert(p.X);
    
            tw.Indent--;
            tw.WriteLine("}");
            tw.WriteLine();
        }

        void WriteParamAssert(byte[] bytes, [CallerArgumentExpression(nameof(bytes))] string name = null)
        {
            tw.WriteLine($"AssertEqual({name}, \"{Convert.ToHexString(bytes)}\");");
        }
         */

        [TestMethod]
        public void Key_DSA() // (Pbits=3072, Qbits=256)
        {
            DsaKey dsaKey = GetDsaKey("Key.DSA.txt");

            DSAParameters p = dsaKey.GetDSAParameters();

            AssertEqual(p.P, "B4074B11CF845F4ECFA4F26AD703DC168D7BC4903BA9A600FC47FEF4F36975EDCEE9916E703654EB9C60FF022EF9EE45023D6D2EDC00DD5DE1017DC2D218F94EC7BC23CE27A20EC9A366F473F31418463202CA29A44C8F4EC867E38FA53723377BD38E34AFA43FD66D13D063EBF7FB1A4176FF7B3B550D282C115650B88718A584055C2712CB8DABFFF94424ACD53C365522E99C50BD10CD7CA6A756524566374C6DBD1C74472361B42854D107F5F5ED5DA58F2B7622572CBB8A5F156EE4C92478B18FB13E739CAE13236F00B7DC687909D785C803FDD748BECDB89D5BA385FC1437C6B02EEADE4E1583032160B6412EC720801A4D0EC23A41A8A1DE1B03AFB6BC12316CCEC5C697D5E484E8B6C8DBCE2358F45987C12DBAD17ECA67B5C7F2456D80964302E316572BB01496688163509058A3325EF6FC0107849D20C7E48FFFF6E82966B62188D3C4407CC58A0CEFF534723F2D1F99D60DD1AC65B03BF7C85CDB11EA04A9E6E5785B19BF16CEDCD117B8E7C00754C9F57BC7DA130AECDCED43");
            AssertEqual(p.G, "0A3EEC4980455848A1A71EC92307C49CA09DF184C17C22D6AECE59C2B84D0F83C880C83DACBC5073BEA4058BAA9E76F4C31C11DD1995C881C1F0A0FB73F021139B423B977655AC95AFF0131ED5B24C69DE8D3DCDDCD62D1E50DF7C92D06C28075675992BD32FAFE1F851A3746C1A8E4AF49852C1C701AF4E28759A233E172EA0666D9C2CC3E1418959B59781689F99528B3B53EEACCBADA2F6543F093E703A4A9F4350DA76E05F07DF979431A9E7F6374EED40F4DAAD87143A54666850F314CEDCE3621CB6E315DEE72CA20BC90FE9BF861FBA925D22D9AABE5230CA037A033C0CDCF6B6E514D7ECFC92D7A09745D306B27148AD5AEEBB8DF5A88A2EBADE786D255D2E6DA7E6C1E7A55CB60287974B33AF0ECF12EACABEF5A5E17D3E85DB745DA475DADC79C65DB83F6ACE105EE5D4CE99C3670443E9B67ED1E73D1B7F48814E2101AD0050CB59CC1DCE0E3BD3F2A75A7007EF8E3D5DA1009032E7DBF867C7E65DA638557FF8C9919F429855651F748FA24A7CA2E0733F1B0AC84D8CB0F3034D");
            AssertEqual(p.Y, "02B1159077248FD9F4BB8966175FAE763E31941AF25C4EFD9E317E8EE0A0954CB861EEC611450D35CBC5ED7B3F6A688F2CE5ABD2285293C479E045AB5FFA206CC4ED17A34ACD6FA9C9885C3082ED7BE7AB18BD0148C19A8545C635A125C4A6C0F70E23763F99F940DA71257CCACFBD5C3832DA18F8FFEBA5689EBA335F6CEA01A650C3282C5C3591393F705E7504313CA9380BD822F0A72BA4922C7AF0C2271A065F2B80008D681A4258EA1BC2880357F7A2AA2D27AECAF1F32CCED545A22D79A6E0F4CA76E9EF890210312A51FA5DB87DA75B00EF6F80E71EF1880B6BCBD50AABAB35FC5BB4CB8C43640C53804BC73A20F00E03425CC4C940F2C10949F50025CC230D272F4F9B6F61C74428D107AEBB4F7E3425D318C8548B457E9FA310BDB57F05D09850DC96D1A581D6B34F6C694BF4DBE6AFBAA200402D27D482D8EA1B95CC573A89B1DE3576BC9194D0CC9B74639FDDB11C67DF1E6D1C32ABE0647001CBAB2ABFA022D74DD3738070A0D5B9FCFD2E68CF1F61242DD9FDA2520DABF949A8");
            AssertEqual(p.Q, "972291E4FC3BCFFF8E981AA95F20583C003D6C3C625CFD22A9184A09D5CA35E9");
            AssertEqual(p.X, "4802142528FF7D162CA3F6F1154249D3168AD3CBB91EEB17C3E84259C0AA4065");
        }

        [TestMethod]
        public void Key_SSH2_DSA_Encrypted_Des_Ede3_CBC_12345() // (Pbits=1024, Qbits=160)
        {
            DsaKey dsaKey = GetDsaKey("Key.SSH2.DSA.Encrypted.Des.Ede3.CBC.12345.txt", "12345");

            DSAParameters p = dsaKey.GetDSAParameters();

            AssertEqual(p.P, "8F20C8715C86456190F8B0921923143A8DEB0DA71564EA572F6C2E316CDFCA0458B329030F7E735DF67AB529B4084D43A2595005591A596FFF7579864B120F20A17BD598E487EC3A587A5F475C642C012B2B04CD094FC8C16A02D6DCF6EBFBA1458DCC17EF11BB55E9637F5667265DFEDDCA8DC40555DB04574F97534A0BB5BD");
            AssertEqual(p.G, "04B63D3DBA0C7F4DD97A6E8ED7EA65F5EE17205602317188F954D38D83693A20799116B88BBE261A4BAF26201E121B78E6BEFC5B5C01AA4756D6054AEFF749F4C29C7172EB8DA02172949432BAA524CD2B141DBD1631C9DC67FB4142DF8D267441D59A7DB30F27DB4A1CA60DD654F75A5D3B5CE2993CDCD601EB2C06E9414FBE");
            AssertEqual(p.Y, "17F837B9770A37DCB325F56F08BC0E1D63C435C2C85DC9C006273872FAA605F5D09CC03D4F83EE046CF8D83E6CC9A29B15ACAF7BBFD421C7261C5CCAFF887867806C1DF6760DCF348AC7AEB9BE44A3CF27895A9790F9FBCD57708B22D3F4D72A5B52B78CFACF95CF5C28AF98E82CA7034B85F4A10D1121564D1079DE92E2EE16");
            AssertEqual(p.Q, "D8D7E6D3B7BB3688D998A011380BD85D5910B279");
            AssertEqual(p.X, "23FA5A574AF1197B185B88008A7A7527899FD092");
        }

        [TestMethod]
        public void Key_SSH2_DSA() // (Pbits=2048, Qbits=256)
        {
            DsaKey dsaKey = GetDsaKey("Key.SSH2.DSA.txt");

            DSAParameters p = dsaKey.GetDSAParameters();

            AssertEqual(p.P, "DB3188409F39229EA18C431494DFA5B3D220BECFD5EA974773C0BA4D9A14B0881A03146987C1AFA12648B47F23CC8D99AD37F4D9F8B4C91650D535336BE1DAEDA2DB0ECDD4B5724313F795FD888A2DBEECED276C18C91223F286C3718ACC737B29B346DDDE784EAFB43BE7503586BE0113EBF50D22694768265691ED5F5D5815F2120AA5D97597E0668DD98A6FCB7EE0317074F0708171084301DB9942B88F1190B7A4CA77CE1D5251E99FF5EF45AFF555627581D34C25F9C0ABA8E953C64785E580CD0C65C1353C8FA0085EEB4FB9B523C527F81FEAB19DD08F61A4A777ECC182462DE09CB8C952E0996993FD451E7D204B86FBC7F7B65AC595552861CC66C9");
            AssertEqual(p.G, "BE953C0B9F9253F1868F8AD8D22D563B12B0080C8FA0F2A8476AEA630696C37814837D1B9D52D125FE9AD85D82B21A83E252F7CE426DA38FD70DA255FDD1EDBEE2F5CFDAEB1EDB96BF9FFAF642259C11F384586387C50A1005EAA300785247742284C134752948974FF8FFE8E997EB2D2DD44D83B218FDEB6676E597882AD5ED9E78D2EB3D632D5D5A52AFE01CBA7BCDBF8782F8C9A103983292D7010213AFA833C1CA06731218176E028721C908F067A5C019248C5E4C21B923BC98BFC605402A8E31649A2C69B143962ECF3030DD4AF935FE3350734789215348F0B0DA14A266F7BD965755C9DED272916898601E8EC18EE820F7E9D7297737FE9C3FB90ED1");
            AssertEqual(p.Y, "56DC32071896DB988B59C173261ABF471F02400CDFC2782E04E16F9D02993506ABAEEFE5A6725999495EB9339127113C2D9E01845630298AD83876A03D7C0F3CC479FF5E0A9A33F7DE4D13DB28ADE723EE2E69F922FCFD611925B6C2BB218C0E7F340748886E425B8830583C53BE5E4075CA3F1927FD62D4D8004B80C0EE7DA7D357B90F79AE21CBD2315F200F527992AC6C0D9A537223A721852AD163C1D09998E3A496D647A47C0EDE26AB620C4B17ABA03F2D89A4C4E955D1FAE1485FCA610B75E19533CA403929F53C85D6186ADDBE37686F6918DAF1AE5EED69BCC3349EB0AD04473B03B1DC551C905CCD38B4859113865D9A465DB649D7BF7A32E0F769");
            AssertEqual(p.Q, "CB63B605F8B7DF4E0ED3674B5D7E0C217284E6EF88495918BDDE23197FD104D5");
            AssertEqual(p.X, "C730A6C9449503828BB66BBA07E047C52E7F4AEBCB4EBFBCA872C275B5C19A9E");
        }
    }
}