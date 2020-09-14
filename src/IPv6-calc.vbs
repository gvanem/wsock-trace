Dim Expanded As String
Dim Binary As String
Dim StartAddr As String
Dim EndAddr As String
Dim AddressWords As String

For a As Integer = 0 To 15 Step 2
    Expanded &= thebytes(a).ToString("X2") & thebytes(a + 1).ToString("X2")
    If a < 15 Then Expanded &= ":"
Next

AddressWords.AddRange(Expanded.Split(":".ToCharArray, StringSplitOptions.RemoveEmptyEntries))

If AddressWords.Count <> 8 Then
    TextBoxStatus.Text = "Not a valid IPV6 Address"
    Exit Sub
End If

For Each word As String In AddressWords
    Binary &= Convert.ToString(Convert.ToUInt16(word, 16), 2).PadLeft(16, CChar("0"))
Next

StartAddr = BinaryStringtoIPV6(Binary.Substring(0, prefix).PadRight(128, CChar("0")))
TextBoxStart.Text = StartAddr
EndAddr = BinaryStringtoIPV6(Binary.Substring(0, prefix).PadRight(128, CChar("1")))
TextBoxEnd.Text = EndAddr


Private Function IPV6toBinaryString(IPV6Address As IPAddress) As String
       Dim IPV6Hex As String = ""
       Dim IPV6AddressWords As New List(Of String)
       Dim IPV6BinaryString As String = ""
       Dim IPV6Bytes() As Byte = IPV6Address.GetAddressBytes ' Convert the Address to 16 bytes

       If IPV6Bytes.Count <> 16 Then ' Make Sure it is 16
           Return "Error getting Base Address Bytes"
       End If

       For a = 0 To 15 Step 2 'Turn Bytes into full 4 character words
           IPV6Hex &= IPV6Bytes(a).ToString("X2") & IPV6Bytes(a + 1).ToString("X2")
           If a < 15 Then IPV6Hex &= ":"
       Next

       IPV6AddressWords.AddRange(IPV6Hex.Split(":".ToCharArray, StringSplitOptions.RemoveEmptyEntries))
       'Now split into a list
       If IPV6AddressWords.Count <> 8 Then
           Return "Not a valid IPV6 Address"
       End If

       For Each word As String In IPV6AddressWords
           'convert each 4 char word into 16 binary bits, leading zeros if needed
           IPV6BinaryString &= Convert.ToString(Convert.ToUInt16(word, 16), 2).PadLeft(16, CChar("0"))
       Next
       Return IPV6BinaryString
End Function

Private Function BinaryStringtoIPV6(BinStr As String) As String
    Dim Output As String = ""
    For wordcounter = 0 To 7
        Output &= Convert.ToUInt16(BinStr.Substring(wordcounter * 16, 16), 2).ToString("X4")
        If wordcounter < 7 Then Output &= ":"
    Next
    Return Output
End Function

