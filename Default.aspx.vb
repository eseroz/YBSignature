Imports System
Imports System.Security
Imports System.Security.Cryptography
Imports System.Security.Cryptography.X509Certificates
Imports System.Security.Cryptography.X509Certificates.X509Store
Imports System.Security.Cryptography.Xml
Imports System.Text
Imports System.Xml
Imports FirmaXades
Imports System.Linq
Imports BaseSmartCardCryptoProvider


Partial Class Default4
    Inherits System.Web.UI.Page
    Protected Sub Page_Load(sender As Object, e As EventArgs) Handles Me.Load

    End Sub

    Protected Sub Button1_Click(sender As Object, e As EventArgs)
        'sert1()

        Dim store As New X509Store(StoreName.AddressBook, StoreLocation.CurrentUser)
        store.Open(OpenFlags.ReadOnly)
        Dim certCollection As X509Certificate2Collection = store.Certificates

        Dim certificate As X509Certificate2 = Nothing
        For Each cer As X509Certificate2 In certCollection
            If (cer.Subject = "CN=BAHADIR TIBBİ ALET CİHAZ VE İNŞAAT MAKİNA SANAYİ VE TİCARET ANONİM ŞİRKETİ, SERIALNUMBER=1310105178") Then
                certificate = cer
                Exit For
            End If

        Next
        Dim xml As String = "C:\Users\inspiron\Desktop\YBSignature\BHDB002017050.xml"
        signEracun(xml, certificate)
    End Sub

    Private Function signEracun(ByVal xml As String, ByVal certificate As X509Certificate2) As String

        Dim CSP As BaseSmartCardCryptoProvider


        CSP.BaseSmartCardCryptoProvider.GetCertificates()



        Dim xmlDoc As XmlDocument = New XmlDocument()
        xmlDoc.PreserveWhitespace = False

        xmlDoc.Load(xml)

        Dim signedXml As FirmaXades.XadesSignedXml = New FirmaXades.XadesSignedXml(xmlDoc)
        signedXml.Signature.Id = "SignatureId"

        Dim URI As String = "http://uri.etsi.org/01903/v1.1.1#"

        Dim qualifyingPropertiesRoot As XmlElement
        qualifyingPropertiesRoot = xmlDoc.CreateElement("xds", "QualifyingProperties", URI)
        qualifyingPropertiesRoot.SetAttribute("Target", "#SignatureId")

        Dim signaturePropertiesRoot As XmlElement
        signaturePropertiesRoot = xmlDoc.CreateElement("xds", "SignedProperties", URI)
        signaturePropertiesRoot.SetAttribute("Id", "SignedPropertiesId")

        Dim SignedSignatureProperties As XmlElement = xmlDoc.CreateElement("xds", "SignedSignatureProperties", URI)

        Dim timestamp As XmlElement = xmlDoc.CreateElement("xds", "SigningTime", URI)
        timestamp.InnerText = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        SignedSignatureProperties.AppendChild(timestamp)

        Dim SigningCertificate As XmlElement = xmlDoc.CreateElement("xds", "SigningCertificate", URI)

        Dim Cert As XmlElement = xmlDoc.CreateElement("xds", "Cert", URI)

        Dim CertDigest As XmlElement = xmlDoc.CreateElement("xds", "CertDigest", URI)

        Dim cryptoServiceProvider As SHA1 = New SHA1CryptoServiceProvider()

        Dim sha1 As Byte() = cryptoServiceProvider.ComputeHash(certificate.RawData)

        Dim DigestMethod As XmlElement = xmlDoc.CreateElement("xds", "DigestMethod", URI)
        DigestMethod.SetAttribute("Algorithm", signedXml.XmlDsigSHA1Url)

        Dim DigestValue As XmlElement = xmlDoc.CreateElement("xds", "DigestValue", URI)
        DigestValue.InnerText = Convert.ToBase64String(sha1)

        CertDigest.AppendChild(DigestMethod)
        CertDigest.AppendChild(DigestValue)
        Cert.AppendChild(CertDigest)

        Dim IssuerSerial As XmlElement = xmlDoc.CreateElement("xds", "IssuerSerial", URI)
        Dim X509IssuerName As XmlElement = xmlDoc.CreateElement("ds", "X509IssuerName", "http://www.w3.org/2000/09/xmldsig#")
        X509IssuerName.InnerText = certificate.IssuerName.Name
        IssuerSerial.AppendChild(X509IssuerName)

        Dim X509SerialNumber As XmlElement = xmlDoc.CreateElement("ds", "X509SerialNumber", "http://www.w3.org/2000/09/xmldsig#")
        X509SerialNumber.InnerText = certificate.SerialNumber
        IssuerSerial.AppendChild(X509SerialNumber)

        Cert.AppendChild(IssuerSerial)

        SigningCertificate.AppendChild(Cert)

        SignedSignatureProperties.AppendChild(SigningCertificate)
        signaturePropertiesRoot.AppendChild(SignedSignatureProperties)
        qualifyingPropertiesRoot.AppendChild(signaturePropertiesRoot)
        Dim dataObject As DataObject = New DataObject With {.Data = qualifyingPropertiesRoot.SelectNodes(".")}
        signedXml.AddObject(dataObject)

        signedXml.SigningKey = certificate.PublicKey.Key



        Dim keyInfo As KeyInfo = New KeyInfo()
        Dim keyInfoX509Data As KeyInfoX509Data = New KeyInfoX509Data(certificate, X509IncludeOption.ExcludeRoot)
        keyInfo.AddClause(keyInfoX509Data)
        signedXml.KeyInfo = keyInfo

        Dim reference2 As Reference = New Reference()
        reference2.Uri = ""
        reference2.AddTransform(New XmlDsigEnvelopedSignatureTransform())
        signedXml.AddReference(reference2)






        'reference2.Type = "http://www.gzs.si/shemas/eslog/racun/1.5#Racun"
        'reference2.Uri = "#data"
        'signedXml.AddReference(reference2)

        'reference2 = New Reference()
        'reference2.Type = "http://uri.etsi.org/01903/v1.1.1/#"
        'reference2.Uri = "#SignedPropertiesId"
        'signedXml.AddReference(reference2)

        signedXml.ComputeSignature()

        Dim xmlDigitalSignature As XmlElement = signedXml.GetXml()
        xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, True))
        Dim checkSign As Boolean = signedXml.CheckSignature()
        Return xmlDoc.OuterXml
    End Function

    Sub sert1()

        Dim store As New X509Store(StoreName.AddressBook, StoreLocation.CurrentUser)
        store.Open(OpenFlags.[ReadOnly])
        Dim certificateCollection As X509Certificate2Collection = store.Certificates

        Response.Write("Sertifika sayısı:" + Str(certificateCollection.Count))
        For Each Certificate In certificateCollection
            Dim rawdata As Byte() = Certificate.RawData
            Response.Write("<li>" + "Content Type: ")
            Response.Write(X509Certificate2.GetCertContentType(rawdata))
            Response.Write("<li>" + "Friendly Name: ")
            Response.Write(Certificate.FriendlyName)
            Response.Write("<li>" + "Archived: ")
            Response.Write(Certificate.Archived)
            Response.Write("<li>" + "Extension: ")
            Response.Write(Certificate.Extensions)
            Response.Write("<li>" + "Handle: ")
            Response.Write(Certificate.Handle)
            Response.Write("<li>" + "HasPrivateKey: ")
            Response.Write(Certificate.HasPrivateKey)
            Response.Write("<li>" + "PrivateKey: ")
            Response.Write(Certificate.PrivateKey)
            Response.Write("<li>" + "PuplicKey: ")
            Response.Write(Certificate.PublicKey)
            Response.Write("<li>" + "SignatureAlgorithm: ")
            Response.Write(Certificate.SignatureAlgorithm)
            Response.Write("<li>" + "Certificate Verified : ")
            Response.Write(Certificate.Verify())
            Response.Write("<li>" + "Simple Name: ")
            Response.Write(Certificate.GetNameInfo(X509NameType.SimpleName, True))
            Response.Write("<li>" + "Signature Algorithm: ")
            Response.Write(Certificate.SignatureAlgorithm.FriendlyName)
            Response.Write("<li>" + "Certificate Archived : ")
            Response.Write(Certificate.Archived)
            Response.Write("<li>" + "Length of Raw Data: ")
            Response.Write(Certificate.RawData.Length)
            Response.Write("<li>" + "Subject: ")
            Response.Write(Certificate.Subject)
            Response.Write("<li>" + "Subject Name: ")
            Response.Write(Certificate.SubjectName)
            Response.Write("<li>" + "Issuer: ")
            Response.Write(Certificate.Issuer)
            Response.Write("<li>" + "Issuer Name: ")
            Response.Write(Certificate.IssuerName)
            Response.Write("<li>" + "Version: ")
            Response.Write(Certificate.Version)
            Response.Write("<li>" + "Valid Date: ")
            Response.Write(Certificate.NotBefore)
            Response.Write("<li>" + "Expiry Date: ")
            Response.Write(Certificate.NotAfter)
            Response.Write("<li>" + "Thumbprint: ")
            Response.Write(Certificate.Thumbprint)
            Response.Write("<li>" + "Serial Number: ")
            Response.Write(Certificate.SerialNumber)
            Response.Write("<li>" + "Friendly Name: ")
            Response.Write(Certificate.PublicKey.Oid.FriendlyName)
            Response.Write("<li>" + "Public Key Format: ")
            Response.Write(Certificate.PublicKey.EncodedKeyValue.Format(True))
            Response.Write("<li>" + "Raw Data Length: ")
            Response.Write(Certificate.RawData.Length)
            Response.Write("<li>" + "Certificate to string: ")
            Response.Write(Certificate.ToString(True))
            Response.Write("<li>" + "Certificate to XML String: ")
            Response.Write(Certificate.PublicKey.Key.ToXmlString(False))

            X509Certificate2UI.DisplayCertificate(Certificate)

            Certificate.Reset()
            Response.Write("<li>" + "-----------------------")
        Next Certificate
        store.Close()
    End Sub


End Class
